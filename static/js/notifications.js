// The Notifications screen: turning push on for this device, the keys a script
// needs, and every device that gets pushes. A subscription outlives a session,
// so this list is how a lost phone stops getting them.
const Notifications = {
  worker: null,
  me: null,

  supported() {
    return "serviceWorker" in navigator && "PushManager" in window && "Notification" in window;
  },

  async init( me ) {
    this.me = me;
    if ( this.supported() ) this.worker = navigator.serviceWorker.register( "/sw.js" );

    Dom.get( "notify-enable" ).addEventListener( "click" , () => this.enable() );
    Dom.get( "notify-prompt-enable" ).addEventListener( "click" , () => this.enable() );
    const test = Dom.get( "notify-test" );
    test.addEventListener( "click" , () => Dom.busy( test , () => this.test() ) );
    Dom.get( "user-key-copy" ).addEventListener( "click" , () => Dom.copy( Dom.get( "user-key" ) ) );
    Dom.get( "user-key-rotate" ).addEventListener( "click" , () => this.rotateKey() );

    if ( me.role === "admin" ) {
      Dom.show( Dom.get( "people-keys" ) , true );
      await this.refreshPeople();
    }
    await this.refresh();
  },

  // The permission prompt only appears from a tap, and awaiting anything before
  // it can lose the tap, so it comes first.
  async enable() {
    const permission = await Notification.requestPermission();
    if ( permission === "granted" ) {
      try {
        await this.worker;
        const registration = await navigator.serviceWorker.ready;
        const key = await Api.request( "/api/push/key" );
        const subscription = await registration.pushManager.subscribe( {
          userVisibleOnly: true,
          applicationServerKey: this.keyBytes( key.public_key ),
        } );
        const details = subscription.toJSON();
        await Api.post( "/api/push/subscribe" , { endpoint: details.endpoint , keys: details.keys } );
      } catch ( error ) {
        App.showError( error.message );
      }
    }
    await this.refresh();
  },

  keyBytes( value ) {
    const padded = value.replace( /-/g , "+" ).replace( /_/g , "/" ) + "=".repeat( ( 4 - value.length % 4 ) % 4 );
    return Uint8Array.from( window.atob( padded ) , ( character ) => character.charCodeAt( 0 ) );
  },

  async subscription() {
    if ( !this.worker ) return null;
    try {
      const registration = await this.worker;
      return await registration.pushManager.getSubscription();
    } catch ( error ) {
      return null;
    }
  },

  // Signing out on a device stops pushes to it. Called before the session ends,
  // because the call needs one. A failure must not stop the sign-out.
  async unsubscribe() {
    const subscription = await this.subscription();
    if ( !subscription ) return;
    try {
      await Api.post( "/api/push/unsubscribe" , { endpoint: subscription.endpoint } );
      await subscription.unsubscribe();
    } catch ( error ) { /* the devices list can still remove it */ }
  },

  async test() {
    const box = Dom.get( "notify-result" );
    try {
      const answer = await Api.post( "/api/push/test" );
      const lines = answer.results.map( ( result ) => [ result.status , result.reason ].filter( Boolean ).join( " " ) );
      Dom.text( box , lines.length > 0 ? I18n.get( "notifications.test_sent" ).replace( "{results}" , () => lines.join( ", " ) ) : I18n.get( "notifications.test_no_devices" ) );
    } catch ( error ) {
      Dom.text( box , error.message );
    }
    Dom.show( box , true );
  },

  statusKey( subscribed ) {
    if ( !this.supported() ) return Install.onIOS() ? "notifications.status_install_first" : "notifications.status_unsupported";
    if ( Notification.permission === "denied" ) return "notifications.status_denied";
    return subscribed ? "notifications.status_on" : "notifications.status_off";
  },

  async refresh() {
    const subscribed = ( await this.subscription() ) !== null;
    const canAsk = this.supported() && Notification.permission !== "denied" && !subscribed;
    Dom.text( Dom.get( "notify-status" ) , I18n.get( this.statusKey( subscribed ) ) );
    Dom.show( Dom.get( "notify-enable" ) , canAsk );
    Dom.show( Dom.get( "notify-test" ) , subscribed );
    Dom.show( Dom.get( "notify-prompt" ) , canAsk );

    const mine = await Api.request( "/api/push/me" );
    Dom.text( Dom.get( "user-key" ) , mine.user_key );
    this.renderDevices( mine.devices );
  },

  deviceName( userAgent ) {
    const names = [ "iPhone" , "iPad" , "Android" , "Macintosh" , "Windows" , "Linux" ];
    const found = names.find( ( name ) => userAgent.indexOf( name ) !== -1 );
    return found === "Macintosh" ? "Mac" : found || I18n.get( "notifications.device_unknown" );
  },

  renderDevices( devices ) {
    const body = Dom.get( "devices-table" ).querySelector( "tbody" );
    Dom.clear( body );
    if ( devices.length === 0 ) Pager.empty( Dom.get( "devices-table" ) );
    devices.forEach( ( device ) => {
      body.appendChild( Dom.el( "tr" , { children: [
        Dom.el( "td" , { text: this.deviceName( device.user_agent ) } ),
        Dom.el( "td" , { children: [ Dom.when( device.created_at ) ] } ),
        Dom.el( "td" , { class: "text-end" , children: [ Dom.el( "button" , {
          class: "btn btn-sm btn-outline-danger",
          text: I18n.get( "notifications.device_remove" ),
          on: { click: () => this.removeDevice( device ) },
        } ) ] } ),
      ] } ) );
    } );
  },

  // Not undoable: the browser would have to subscribe again.
  async removeDevice( device ) {
    if ( !await Dom.confirm( I18n.get( "notifications.device_remove_confirm" ) ) ) return;
    try {
      await Api.post( "/api/push/devices/" + device.id + "/delete" );
      await this.refresh();
    } catch ( error ) {
      App.showError( error.message );
    }
  },

  async rotateKey() {
    if ( !await Dom.confirm( I18n.get( "notifications.key_rotate_confirm" ) ) ) return;
    try {
      const rotated = await Api.post( "/api/push/rotate-key" );
      Dom.text( Dom.get( "user-key" ) , rotated.user_key );
      if ( this.me.role === "admin" ) await this.refreshPeople();
    } catch ( error ) {
      App.showError( error.message );
    }
  },

  refreshPeople() {
    return Pager.load( "people-table" , "people" ,
      ( offset ) => Api.request( "/api/admin/recipient-keys" + Api.query( { offset: offset } ) ) ,
      ( person ) => {
        const key = Dom.el( "code" , { text: person.user_key } );
        Dom.get( "people-table" ).querySelector( "tbody" ).appendChild( Dom.el( "tr" , { children: [
          Dom.el( "td" , { class: "text-break" , children: [
            Dom.el( "div" , { class: "fw-semibold" , text: person.display_name } ),
            key,
          ] } ),
          Dom.el( "td" , { class: "text-end" , children: [ Dom.el( "button" , {
            class: "btn btn-sm btn-outline-secondary",
            text: I18n.get( "account.copy_button" ),
            on: { click: () => Dom.copy( key ) },
          } ) ] } ),
        ] } ) );
      } );
  },
};
