// The Webhooks screen (owner only): endpoints that hear about what happens
// here, and how each delivery went. app.js calls Webhooks.init( me ) for admins;
// only the owner gets past the first line, and the server answers anyone else
// with a 404 regardless.
//
// Names, addresses and error text are other people's text, so every one goes
// through textContent. See the note at the top of dom.js.
const Webhooks = {
  // The endpoint whose deliveries are showing, and what the form offers.
  open: null,
  events: [],

  async init( me ) {
    if ( !me.is_owner || me.webhooks_enabled === false ) return;
    Dom.show( Dom.get( "webhooks-panel" ) , true );
    Dom.onSubmit( Dom.get( "create-webhook-form" ) , this.onCreate.bind( this ) );
    Dom.get( "copy-webhook-button" ).addEventListener( "click" , this.onCopy.bind( this ) );
    Dom.get( "webhook-all-events" ).addEventListener( "change" , this.syncEvents.bind( this ) );
    try {
      const catalogue = await Api.webhookEvents();
      this.renderEvents( catalogue.events );
    } catch ( error ) {
      App.showError( error.message );
    }
    await this.refresh();
  },

  // One checkbox per event. The names are the ones a receiver sees, so they
  // are shown as they are rather than translated.
  renderEvents( events ) {
    this.events = events;
    const holder = Dom.get( "webhook-events" );
    Dom.clear( holder );
    events.forEach( function ( event , index ) {
      const id = "webhook-event-" + index;
      holder.appendChild( Dom.el( "div" , { class: "form-check" , children: [
        Dom.el( "input" , { class: "form-check-input" , attrs: { id: id , type: "checkbox" , value: event } } ),
        Dom.el( "label" , { class: "form-check-label" , text: event , attrs: { for: id } } ),
      ] } ) );
    } );
    this.syncEvents();
  },

  syncEvents() {
    const all = Dom.get( "webhook-all-events" ).checked;
    Dom.show( Dom.get( "webhook-events" ) , !all );
  },

  pickedEvents() {
    if ( Dom.get( "webhook-all-events" ).checked ) return [ "*" ];
    return Array.from( Dom.get( "webhook-events" ).querySelectorAll( "input:checked" ) ).map( ( box ) => box.value );
  },

  async onCreate( event ) {
    event.preventDefault();
    const name = Dom.get( "webhook-name" ).value.trim();
    const url = Dom.get( "webhook-url" ).value.trim();
    try {
      const created = await Api.createWebhook( name , url , this.pickedEvents() );
      this.showSecret( created.secret , I18n.get( "webhooks.secret_notice" ) );
      Dom.get( "webhook-name" ).value = "";
      Dom.get( "webhook-url" ).value = "";
      await this.refresh();
    } catch ( error ) {
      App.showError( error.message );
    }
  },

  // Shown once: no route gives a signing secret out again.
  showSecret( secret , notice ) {
    const box = Dom.get( "webhook-secret-box" );
    Dom.text( Dom.get( "webhook-secret-notice" ) , notice );
    Dom.text( Dom.get( "webhook-secret-value" ) , secret );
    Dom.show( box , true );
    box.scrollIntoView( { block: "nearest" } );
  },

  async onCopy() {
    await Dom.copy( Dom.get( "webhook-secret-value" ) );
  },

  button( key , tone , onClick ) {
    return Dom.el( "button" , {
      class: "btn btn-sm btn-outline-" + tone,
      text: I18n.get( key ),
      on: { click: onClick },
    } );
  },

  // The name edits in place, with undo. It is the owner's text, and
  // Dom.editable builds with textContent.
  nameCell( hook ) {
    const rename = ( name , expect ) => Api.renameWebhook( hook.id , name , expect );
    return Dom.editable( hook.name , {
      label: I18n.get( "webhooks.table_name" ),
      maxLength: 80,
      save: async ( value ) => {
        const previous = hook.name;
        await rename( value , previous );
        hook.name = value;
        this.nameDeliveries( hook );
        Undo.record( {
          label: I18n.get( "undo.rename_webhook" ),
          toast: true,
          undo: async () => { await rename( previous , value ); await this.refresh(); },
          redo: async () => { await rename( value , previous ); await this.refresh(); },
        } );
      },
    } );
  },

  // The address and the events. It can undo, unlike a key's expiry: the old
  // values are exact, and an address with a token in it is hard to get back.
  async onEdit( hook ) {
    const previous = { url: hook.url , events: hook.events };
    const everything = { value: "*" , label: I18n.get( "webhooks.all_events" ) };
    const next = await Dom.form( {
      title: I18n.get( "webhooks.edit_heading" ).replace( "{name}" , () => hook.name ),
      fields: [
        { name: "url" , label: I18n.get( "webhooks.url_label" ) , type: "url" , maxLength: 2000 , value: hook.url , required: true , help: I18n.get( "webhooks.edit_url_help" ) },
        { name: "events" , label: I18n.get( "webhooks.events_label" ) , type: "checks" , value: hook.events ,
          options: [ everything ].concat( this.events.map( ( event ) => ( { value: event , label: event } ) ) ) },
      ],
      save: async ( values ) => {
        const target = { url: values.url , events: values.events.includes( "*" ) ? [ "*" ] : values.events };
        if ( JSON.stringify( target ) === JSON.stringify( previous ) ) return false;
        await Api.setWebhookTarget( hook.id , target , previous );
        return target;
      },
    } );
    if ( !next ) return;
    try {
      await this.refresh();
    } catch ( error ) { App.showError( error.message ); }
    Undo.record( {
      label: I18n.get( "undo.edit_webhook" ),
      toast: true,
      undo: async () => { await Api.setWebhookTarget( hook.id , previous , next ); await this.refresh(); },
      redo: async () => { await Api.setWebhookTarget( hook.id , next , previous ); await this.refresh(); },
    } );
  },

  // No undo: the old secret is gone, so it asks first.
  async onRotate( hook ) {
    const question = I18n.get( "webhooks.rotate_confirm" ).replace( "{name}" , () => hook.name );
    if ( !( await Dom.confirm( question ) ) ) return;
    try {
      const rotated = await Api.rotateWebhookSecret( hook.id );
      this.showSecret( rotated.secret , I18n.get( "webhooks.rotated_notice" ).replace( "{name}" , () => hook.name ) );
    } catch ( error ) { App.showError( error.message ); }
  },

  async refresh() {
    const body = Dom.get( "webhooks-table" ).querySelector( "tbody" );
    await Pager.load( "webhooks-table" , "webhooks" , ( offset ) => Api.webhooks( offset ) , ( hook ) => {
      if ( this.open && this.open.id === hook.id ) this.nameDeliveries( hook );
      const edit = this.button( "webhooks.edit_button" , "secondary" , () => this.onEdit( hook ) );
      const rotate = this.button( "webhooks.rotate_button" , "secondary" , () => this.onRotate( hook ) );
      const toggle = this.button( hook.enabled ? "webhooks.disable_button" : "webhooks.enable_button" , "secondary" , async () => {
        try {
          await Api.setWebhookEnabled( hook.id , !hook.enabled );
          await this.refresh();
        } catch ( error ) { App.showError( error.message ); }
      } );
      const test = this.button( "webhooks.test_button" , "secondary" , async () => {
        try {
          await Api.testWebhook( hook.id );
          await this.showDeliveries( hook );
          Dom.toast( I18n.get( "webhooks.test_sent" ) , "ok" );
        } catch ( error ) { App.showError( error.message ); }
      } );
      const history = this.button( "webhooks.deliveries_button" , "secondary" , () => this.showDeliveries( hook ) );
      // Delete asks nothing and offers Undo, like an invite link.
      const remove = this.button( "webhooks.delete_button" , "danger" , async () => {
        try {
          await Api.deleteWebhook( hook.id );
          if ( this.open && this.open.id === hook.id ) this.closeDeliveries();
          await this.refresh();
        } catch ( error ) {
          App.showError( error.message );
          return;
        }
        Undo.record( {
          label: I18n.get( "undo.deleted_webhook" ),
          toast: true,
          undo: async () => { await Api.restoreWebhook( hook.id ); await this.refresh(); },
          redo: async () => { await Api.deleteWebhook( hook.id ); await this.refresh(); },
        } );
      } );

      body.appendChild( Dom.el( "tr" , { children: [
        Dom.el( "td" , { children: [ this.nameCell( hook ) ] } ),
        Dom.el( "td" , { class: "text-break" , text: hook.url } ),
        Dom.el( "td" , { children: [ hook.enabled
          ? Dom.badge( I18n.get( "webhooks.status_on" ) , "success" )
          : Dom.badge( I18n.get( "webhooks.status_off" ) , "secondary" ) ] } ),
        Dom.el( "td" , { children: [
          Dom.el( "div" , { class: "row-actions" , children: [ edit , toggle , test , history , rotate , remove ] } ),
        ] } ),
      ] } ) );
    } );
  },

  closeDeliveries() {
    this.open = null;
    Dom.show( Dom.get( "webhook-deliveries" ) , false );
  },

  deliveryBadge( delivery ) {
    if ( delivery.status === "delivered" ) return Dom.badge( I18n.get( "webhooks.delivery_delivered" ) , "success" );
    if ( delivery.status === "failed" ) return Dom.badge( I18n.get( "webhooks.delivery_failed" ) , "danger" );
    return Dom.badge( I18n.get( "webhooks.delivery_pending" ) , "warning" );
  },

  // Keeps the heading right when the endpoint is renamed under it.
  nameDeliveries( hook ) {
    if ( !this.open || this.open.id !== hook.id ) return;
    this.open = hook;
    Dom.text( Dom.get( "webhook-deliveries-heading" ) , I18n.get( "webhooks.deliveries_heading" ).replace( "{name}" , () => hook.name ) );
  },

  async showDeliveries( hook ) {
    this.open = hook;
    this.nameDeliveries( hook );
    Dom.show( Dom.get( "webhook-deliveries" ) , true );
    const body = Dom.get( "webhook-deliveries-table" ).querySelector( "tbody" );
    await Pager.load( "webhook-deliveries-table" , "deliveries" , ( offset ) => Api.webhookDeliveries( hook.id , offset ) , ( delivery ) => {
      body.appendChild( Dom.el( "tr" , { children: [
        Dom.el( "td" , { text: delivery.event } ),
        Dom.el( "td" , { children: [ this.deliveryBadge( delivery ) ] } ),
        Dom.el( "td" , { text: String( delivery.attempts ) } ),
        Dom.el( "td" , { class: "text-break" , text: delivery.last_error || ( delivery.last_status ? String( delivery.last_status ) : "" ) } ),
        Dom.el( "td" , { children: [ Dom.when( delivery.created_at ) ] } ),
        Dom.el( "td" , { children: delivery.status === "failed" ? [ this.resendButton( hook , delivery ) ] : [] } ),
      ] } ) );
    } );
  },

  // Once the receiver is fixed. The failed row stays, and a new one appears.
  resendButton( hook , delivery ) {
    return Dom.el( "button" , {
      class: "btn btn-sm btn-outline-secondary",
      text: I18n.get( "webhooks.resend_button" ),
      on: { click: async () => {
        try {
          await Api.resendDelivery( hook.id , delivery.id );
          Dom.toast( I18n.get( "webhooks.resent" ) , "ok" );
          await this.showDeliveries( this.open );
        } catch ( error ) { App.showError( error.message ); }
      } },
    } );
  },
};
