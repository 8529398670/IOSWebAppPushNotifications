// The Apps screen. A virtual app is a name, an icon, a sound and a token, and
// everyone sees them all, because anyone may want to mute one. Only whoever made
// an app, or an admin, can change it.
const Apps = {
  // Icons are drawn opaque on white: iOS would show transparency as black.
  iconSide: 256,
  rows: [],

  async init() {
    Dom.onSubmit( Dom.get( "create-app-form" ) , this.onCreate.bind( this ) );
    Dom.get( "app-token-copy" ).addEventListener( "click" , () => Dom.copy( Dom.get( "app-token-value" ) ) );
    Dom.get( "app-token-example-copy" ).addEventListener( "click" , () => Dom.copy( Dom.get( "app-token-example" ) ) );
    await this.refresh();
  },

  refresh() {
    this.rows = [];
    return Pager.load( "apps-table" , "apps" ,
      ( offset ) => Api.request( "/api/apps" + Api.query( { offset: offset } ) ) ,
      ( app ) => {
        this.rows.push( app );
        Dom.get( "apps-table" ).querySelector( "tbody" ).appendChild( this.row( app ) );
      } );
  },

  // Shown once: no route gives a token out again. The example has this person's
  // real key in it, so it works as copied: a placeholder would be sent as it is.
  async showToken( name , token ) {
    const mine = await Api.request( "/api/push/me" );
    Dom.text( Dom.get( "app-token-notice" ) , I18n.get( "apps.token_notice" ).replace( "{name}" , () => name ) );
    Dom.text( Dom.get( "app-token-value" ) , token );
    Dom.text( Dom.get( "app-token-example" ) , "curl " + window.location.origin + "/api/v1/messages -d token=" + token + " -d user=" + mine.user_key + " -d message=Hello" );
    const box = Dom.get( "app-token-box" );
    Dom.show( box , true );
    box.scrollIntoView( { block: "nearest" } );
  },

  async onCreate( event ) {
    event.preventDefault();
    const input = Dom.get( "new-app-name" );
    try {
      const created = await Api.post( "/api/apps" , { name: input.value.trim() } );
      input.value = "";
      await this.showToken( created.name , created.token );
      await this.refresh();
      await Inbox.loadApps();
    } catch ( error ) {
      App.showError( error.message );
    }
  },

  iconCell( app ) {
    if ( !app.has_icon ) {
      return Dom.el( "span" , { class: "app-icon app-icon-blank" , children: [ Dom.el( "i" , { class: "bi bi-app-indicator" , attrs: { "aria-hidden": "true" } } ) ] } );
    }
    return Dom.el( "img" , { class: "app-icon" , attrs: { alt: "" , src: "/api/apps/" + app.id + "/icon?v=" + app.media_version } } );
  },

  button( key , tone , onClick ) {
    return Dom.el( "button" , {
      class: "btn btn-sm btn-outline-" + tone,
      text: I18n.get( key ),
      on: { click: onClick },
    } );
  },

  nameCell( app ) {
    if ( !app.can_manage ) return Dom.el( "span" , { class: "fw-semibold" , text: app.name } );
    return Dom.editable( app.name , {
      label: I18n.get( "apps.name_label" ),
      maxLength: 60,
      save: async ( value ) => {
        const previous = app.name;
        const rename = ( name ) => Api.post( "/api/apps/" + app.id + "/rename" , { name: name } );
        await rename( value );
        app.name = value;
        Undo.record( {
          label: I18n.get( "undo.rename_app" ),
          toast: true,
          undo: async () => { await rename( previous ); await this.refresh(); },
          redo: async () => { await rename( value ); await this.refresh(); },
        } );
      },
    } );
  },

  muteSwitch( app ) {
    const id = "mute-" + app.id;
    const box = Dom.el( "input" , { class: "form-check-input" , attrs: { type: "checkbox" , role: "switch" , id: id } } );
    box.checked = !app.muted;
    const set = async ( muted ) => {
      await Api.post( "/api/apps/" + app.id + "/mute" , { muted: muted } );
      app.muted = muted;
      box.checked = !muted;
    };
    box.addEventListener( "change" , async () => {
      const muted = !box.checked;
      try {
        await Undo.run( {
          label: I18n.get( muted ? "undo.mute_app" : "undo.unmute_app" ),
          do: () => set( muted ),
          undo: () => set( !muted ),
        } );
      } catch ( error ) {
        box.checked = muted;
        App.showError( error.message );
      }
    } );
    return Dom.el( "div" , { class: "form-check form-switch mb-0" , children: [
      box,
      Dom.el( "label" , { class: "form-check-label" , text: I18n.get( "apps.notify_label" ) , attrs: { for: id } } ),
    ] } );
  },

  row( app ) {
    const actions = [ this.muteSwitch( app ) ];
    if ( app.has_sound ) actions.push( this.button( "apps.sound_play" , "secondary" , () => Sounds.preview( app.id , app.media_version ) ) );
    if ( app.can_manage ) {
      actions.push(
        this.button( "apps.icon_button" , "secondary" , () => this.pickFile( "image/*" , ( file ) => this.uploadIcon( app , file ) ) ),
        this.button( "apps.sound_button" , "secondary" , () => this.pickFile( "" , ( file ) => this.uploadSound( app , file ) ) ),
        this.button( "apps.rotate_button" , "secondary" , () => this.rotate( app ) ),
        this.button( "apps.delete_button" , "danger" , () => this.remove( app ) ),
      );
    }
    return Dom.el( "tr" , { children: [ Dom.el( "td" , { children: [
      Dom.el( "div" , { class: "d-flex align-items-center gap-3" , children: [
        this.iconCell( app ),
        Dom.el( "div" , { class: "flex-grow-1 min-w-0" , children: [
          this.nameCell( app ),
          Dom.el( "div" , { class: "small text-body-secondary" , text: app.owner_name } ),
        ] } ),
      ] } ),
      Dom.el( "div" , { class: "d-flex flex-wrap align-items-center gap-2 mt-2" , children: actions } ),
    ] } ) ] } );
  },

  // In the page, not just in memory: iOS can drop an input nothing holds on to,
  // and then no choice ever arrives. An empty accept lets any file be picked,
  // which sounds need, because iOS greys out real audio files under audio/*.
  // The server checks what the file really is.
  pickFile( accept , handle ) {
    const input = Dom.el( "input" , { class: "visually-hidden" , attrs: { type: "file" , tabindex: "-1" , "aria-hidden": "true" } } );
    if ( accept !== "" ) input.setAttribute( "accept" , accept );
    input.addEventListener( "change" , () => {
      if ( input.files.length > 0 ) handle( input.files[ 0 ] );
      input.remove();
    } );
    input.addEventListener( "cancel" , () => input.remove() );
    document.body.appendChild( input );
    input.click();
  },

  // Through createImageBitmap rather than an <img>: the page's security policy
  // has no blob: images. Cropped to a centred square.
  async squareIcon( file ) {
    const bitmap = await createImageBitmap( file );
    const side = Math.min( bitmap.width , bitmap.height );
    const canvas = Dom.el( "canvas" , { attrs: { width: this.iconSide , height: this.iconSide } } );
    const drawing = canvas.getContext( "2d" );
    drawing.fillStyle = "#ffffff";
    drawing.fillRect( 0 , 0 , this.iconSide , this.iconSide );
    drawing.drawImage( bitmap , ( bitmap.width - side ) / 2 , ( bitmap.height - side ) / 2 , side , side , 0 , 0 , this.iconSide , this.iconSide );
    return new Promise( ( resolve ) => canvas.toBlob( resolve , "image/png" ) );
  },

  upload( app , kind , body , type ) {
    return Api.request( "/api/apps/" + app.id + "/" + kind , {
      method: "POST",
      headers: { "Content-Type": type , "X-CSRF-Token": Api.csrfToken },
      raw: body,
    } );
  },

  async uploadIcon( app , file ) {
    try {
      await this.upload( app , "icon" , await this.squareIcon( file ) , "image/png" );
      await this.refresh();
    } catch ( error ) {
      App.showError( error.message );
    }
  },

  async uploadSound( app , file ) {
    try {
      await this.upload( app , "sound" , file , "application/octet-stream" );
      await this.refresh();
    } catch ( error ) {
      App.showError( error.message );
    }
  },

  // Not undoable: the old token is gone, which is the point.
  async rotate( app ) {
    if ( !await Dom.confirm( I18n.get( "apps.rotate_confirm" ).replace( "{name}" , () => app.name ) ) ) return;
    try {
      const rotated = await Api.post( "/api/apps/" + app.id + "/rotate-token" );
      await this.showToken( app.name , rotated.token );
    } catch ( error ) {
      App.showError( error.message );
    }
  },

  async remove( app ) {
    try {
      await Undo.run( {
        label: I18n.get( "undo.delete_app" ),
        toast: true,
        do: async () => { await Api.post( "/api/apps/" + app.id + "/delete" ); await this.refresh(); },
        undo: async () => { await Api.post( "/api/apps/" + app.id + "/restore" ); await this.refresh(); },
      } );
    } catch ( error ) {
      App.showError( error.message );
    }
  },
};
