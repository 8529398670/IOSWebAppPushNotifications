// The browser half of the activity log: what people do on the page. The
// server logs every request it answers on its own; this adds what it cannot
// see -- which screen someone moved to, what they clicked, which form they
// sent, what they undid, and the errors and failed calls their browser hit.
// Only the owner can read the result (logs.js, the Logs screen).
//
// What is never sent: anything typed. A form submit names its fields, not
// their values; a click names the control (its language.yaml key, its id, or
// the first few words of its label), not the page around it. Login links,
// API keys and PINs only ever live in values, so they cannot leak through
// here. A part of the page marked data-no-track is skipped entirely (the
// Logs screen is, or reading the log would fill it).
//
// Events are batched and sent every few seconds, and once more as the page
// goes away (keepalive, so the request outlives the tab). A failed send is
// dropped rather than retried: the log is a record, not a queue anything
// depends on.
const Track = {
  enabled: false,
  clicks: false,
  queue: [],
  batchSize: 50,
  intervalMs: 5000,
  tab: "",
  lastScreen: null,

  // app.js calls this once it knows who is signed in. Signed out, or with
  // logs switched off in config.yaml, every other method is a no-op.
  init( me ) {
    if ( !me.logs_enabled ) return;
    this.enabled = true;
    this.clicks = Boolean( me.logs_ui_clicks );
    // One id per tab, so two tabs of the same person read apart in the log.
    this.tab = Math.random().toString( 36 ).slice( 2 , 10 );
    this.event( "session_start" , { client: this.device() } );

    // Capture phase, so a handler that stops propagation still gets logged.
    document.addEventListener( "click" , ( event ) => this.onClick( event ) , true );
    document.addEventListener( "submit" , ( event ) => this.onSubmit( event ) , true );
    window.addEventListener( "error" , ( event ) => this.onError( event ) );
    window.addEventListener( "unhandledrejection" , ( event ) => this.onRejection( event ) );
    window.setInterval( () => this.flush() , this.intervalMs );
    document.addEventListener( "visibilitychange" , () => {
      if ( document.visibilityState === "hidden" ) this.flush();
    } );
    window.addEventListener( "pagehide" , () => this.flush() );
  },

  // What the server cannot tell from a request: the screen, the zone, the
  // language the browser asks for. The user agent comes from the request
  // headers server-side, so it is not repeated here.
  device() {
    const brands = navigator.userAgentData || null;
    let zone = "";
    try { zone = Intl.DateTimeFormat().resolvedOptions().timeZone || ""; } catch ( error ) { zone = ""; }
    return {
      tz: zone,
      lang: navigator.language || "",
      screen: window.screen.width + "x" + window.screen.height + "@" + ( window.devicePixelRatio || 1 ),
      viewport: window.innerWidth + "x" + window.innerHeight,
      platform: ( brands && brands.platform ) || navigator.platform || "",
      mobile: Boolean( brands && brands.mobile ),
      touch: navigator.maxTouchPoints || 0,
      theme: document.documentElement.getAttribute( "data-bs-theme" ) || "light",
    };
  },

  // Nav is a top-level const, which is not a property of window, so it is
  // looked for by name (the same as Undo.hasNav).
  screen() {
    return typeof Nav !== "undefined" ? Nav.current() : "";
  },

  event( action , fields ) {
    if ( !this.enabled ) return;
    this.queue.push( Object.assign( { action: action , screen: this.screen() , at: new Date().toISOString() } , fields || {} ) );
    if ( this.queue.length >= this.batchSize ) this.flush();
  },

  // Called by Nav.render on every screen change, including the first.
  nav( name ) {
    if ( name === this.lastScreen ) return;
    this.lastScreen = name;
    this.event( "nav" , { screen: name } );
  },

  // Called by Undo.step: "undo" or "redo", with the action's label.
  undo( direction , label ) {
    this.event( direction , { target: label || "" } );
  },

  // Called by Api.request for a call that never got an answer (status 0) or
  // that the server failed (5xx). Its own 4xx answers are the server's to
  // log, and already are.
  failed( path , status ) {
    if ( path.indexOf( "/api/logs/" ) === 0 ) return;
    this.event( "fetch_fail" , { detail: { path: path.split( "?" )[ 0 ] , status: status } } );
  },

  skipped( element ) {
    return Boolean( element.closest( "[data-no-track]" ) );
  },

  // The name a control goes by in the log: its language.yaml key when it has
  // one (stable across copy edits and languages), else its id, else a short
  // piece of its visible label.
  label( element ) {
    const keyed = element.hasAttribute( "data-i18n" ) ? element : element.querySelector( "[data-i18n]" );
    if ( keyed ) return keyed.getAttribute( "data-i18n" );
    if ( element.id ) return "#" + element.id;
    const aria = element.getAttribute( "aria-label" );
    if ( aria ) return aria.slice( 0 , 60 );
    return ( element.textContent || "" ).trim().replace( /\s+/g , " " ).slice( 0 , 40 );
  },

  onClick( event ) {
    if ( !this.clicks || !event.target.closest ) return;
    const control = event.target.closest( "button, a, summary, [role=button], input[type=checkbox], input[type=radio]" );
    if ( !control || this.skipped( control ) ) return;
    const detail = {};
    // A hash link says where it goes; any other href is left out, since a
    // login or invite link is a credential.
    const href = control.getAttribute( "href" );
    if ( href && href.charAt( 0 ) === "#" ) detail.href = href;
    const where = control.closest( "tr" ) ? "row" : "";
    if ( where ) detail.in = where;
    this.event( "click" , { target: this.label( control ) , detail: detail } );
  },

  onSubmit( event ) {
    const form = event.target;
    if ( !form || !form.elements || this.skipped( form ) ) return;
    const names = Array.from( form.elements )
      .map( function ( field ) { return field.name; } )
      .filter( Boolean );
    this.event( "submit" , { target: form.id ? "#" + form.id : "form" , fields: names } );
  },

  onError( event ) {
    this.event( "error" , { detail: {
      message: String( event.message || "" ).slice( 0 , 200 ),
      source: String( event.filename || "" ).split( "?" )[ 0 ],
      line: event.lineno || 0,
      column: event.colno || 0,
    } } );
  },

  onRejection( event ) {
    const reason = event.reason;
    this.event( "error" , { detail: {
      message: String( ( reason && reason.message ) || reason || "" ).slice( 0 , 200 ),
      source: "promise",
    } } );
  },

  // Straight to fetch rather than through Api.request: keepalive lets the
  // last batch outlive a closing tab, and a failure here must not report
  // itself as a failed call (that would loop).
  flush() {
    if ( !this.enabled || this.queue.length === 0 ) return;
    const events = this.queue.splice( 0 , this.batchSize );
    try {
      fetch( "/api/logs/events" , {
        method: "POST",
        credentials: "same-origin",
        keepalive: true,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify( { tab: this.tab , events: events , csrf_token: Api.csrfToken } ),
      } ).catch( function () { /* dropped: see the note at the top */ } );
    } catch ( error ) { /* same */ }
    if ( this.queue.length > 0 ) this.flush();
  },
};
