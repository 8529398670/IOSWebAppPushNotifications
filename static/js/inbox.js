// The Inbox, iPB's first screen: every message, newest first. A push can only
// carry so much, so this is where the whole text and any link live.
const Inbox = {
  apps: {},
  filter: "",
  newest: null,
  loaded: false,

  async init() {
    Dom.get( "inbox-read-all" ).addEventListener( "click" , () => this.readAll() );
    Dom.get( "inbox-filter" ).addEventListener( "change" , async ( event ) => {
      this.filter = event.target.value;
      await this.refresh();
    } );
    document.addEventListener( "visibilitychange" , () => {
      if ( document.visibilityState === "visible" ) this.refresh();
    } );
    await this.loadApps();
    await this.refresh();
    this.listen();
  },

  async loadApps() {
    const page = await Api.request( "/api/apps" + Api.query( { limit: 200 } ) );
    this.apps = {};
    const select = Dom.get( "inbox-filter" );
    const chosen = select.value;
    Dom.clear( select );
    select.appendChild( Dom.el( "option" , { text: I18n.get( "inbox.filter_all" ) , attrs: { value: "" } } ) );
    page.apps.forEach( ( app ) => {
      this.apps[ app.id ] = app;
      select.appendChild( Dom.el( "option" , { text: app.name , attrs: { value: app.id } } ) );
    } );
    select.value = chosen;
  },

  // Tells this page about a new message while it is open. The first frame of a
  // stream is always "changed", so what has already loaded is the baseline, and
  // only a message newer than that makes a sound.
  listen() {
    const source = new EventSource( "/api/inbox/stream" );
    source.addEventListener( "changed" , () => this.refresh() );
  },

  fetchPage( offset ) {
    return Api.request( "/api/inbox" + Api.query( { offset: offset , app: this.filter } ) );
  },

  async refresh() {
    const page = await Pager.load( "inbox-table" , "items" , ( offset ) => this.fetchPage( offset ) ,
      ( item ) => Dom.get( "inbox-table" ).querySelector( "tbody" ).appendChild( this.row( item ) ) );
    if ( page ) this.noticeNew( page.items );
    await this.updateBadge();
  },

  noticeNew( items ) {
    if ( items.length === 0 ) return;
    const top = items[ 0 ];
    const isNew = this.loaded && top.id > ( this.newest || "" );
    if ( !this.newest || top.id > this.newest ) this.newest = top.id;
    this.loaded = true;
    const app = this.apps[ top.app_id ];
    if ( isNew && !top.read && top.priority !== -1 && app && app.has_sound && !app.muted ) {
      Sounds.play( app.id , app.media_version ).catch( () => {} );
    }
  },

  async updateBadge() {
    let count = 0;
    try {
      count = ( await Api.request( "/api/inbox/unread" ) ).unread;
    } catch ( error ) {
      return;
    }
    const badge = Dom.get( "inbox-count" );
    Dom.text( badge , String( count ) );
    Dom.show( badge , count > 0 );
    Dom.show( Dom.get( "inbox-read-all" ) , count > 0 );
    if ( navigator.setAppBadge ) {
      navigator.setAppBadge( count ).catch( () => {} );
    }
  },

  iconFor( item ) {
    const app = this.apps[ item.app_id ];
    if ( app ) return Apps.iconCell( app );
    return Apps.iconCell( { has_icon: false } );
  },

  row( item ) {
    const lines = [
      Dom.el( "div" , { class: "d-flex justify-content-between gap-2" , children: [
        Dom.el( "span" , { class: "small fw-semibold" , text: item.app_name } ),
        Dom.el( "span" , { class: "small text-body-secondary text-nowrap" , text: Dom.ago( new Date( item.created_at ) ) } ),
      ] } ),
    ];
    if ( item.title !== "" ) lines.push( Dom.el( "div" , { class: "fw-semibold" , text: item.title } ) );
    lines.push( Dom.el( "div" , { class: "inbox-body" , text: item.body } ) );
    if ( item.url ) {
      lines.push( Dom.el( "a" , {
        class: "small",
        text: item.url_title || item.url,
        attrs: { href: item.url , target: "_blank" , rel: "noopener noreferrer" },
        on: { click: ( event ) => event.stopPropagation() },
      } ) );
    }
    const remove = Dom.el( "button" , {
      class: "btn-close btn-sm flex-shrink-0",
      attrs: { type: "button" , "aria-label": I18n.get( "inbox.delete_label" ) },
      on: { click: ( event ) => { event.stopPropagation(); this.remove( item ); } },
    } );
    return Dom.el( "tr" , {
      class: item.read ? "inbox-item" : "inbox-item inbox-unread",
      on: { click: () => this.read( item ) },
      children: [ Dom.el( "td" , { children: [ Dom.el( "div" , { class: "d-flex gap-3" , children: [
        this.iconFor( item ),
        Dom.el( "div" , { class: "flex-grow-1 min-w-0" , children: lines } ),
        remove,
      ] } ) ] } ) ],
    } );
  },

  // Reading a priority 2 message is also what stops it repeating.
  async read( item ) {
    if ( item.read ) return;
    try {
      await Api.post( "/api/inbox/" + item.id + "/read" );
      await this.refresh();
    } catch ( error ) {
      App.showError( error.message );
    }
  },

  async readAll() {
    try {
      await Api.post( "/api/inbox/read-all" );
      await this.refresh();
    } catch ( error ) {
      App.showError( error.message );
    }
  },

  async remove( item ) {
    try {
      await Undo.run( {
        label: I18n.get( "undo.delete_message" ),
        toast: true,
        do: async () => { await Api.post( "/api/inbox/" + item.id + "/delete" ); await this.refresh(); },
        undo: async () => { await Api.post( "/api/inbox/" + item.id + "/restore" ); await this.refresh(); },
      } );
    } catch ( error ) {
      App.showError( error.message );
    }
  },
};
