// Two-factor sign-in: the step that asks for a code during any sign-in, and
// the panel where a person turns it on or off. The server decides when a code
// is needed; a sign-in call answers { two_factor: true, challenge } instead of
// signing in, and that is the only signal this file acts on.
const TwoFactor = {
  challenge: "",
  bound: false,
  me: null,

  // --- during sign-in -------------------------------------------------------

  ask( challenge ) {
    this.challenge = challenge;
    [ "signed-out" , "login-confirm" , "join" ].forEach( function ( id ) {
      Dom.show( Dom.get( id ) , false );
    } );
    Dom.show( Dom.get( "two-factor-step" ) , true );
    if ( !this.bound ) {
      this.bound = true;
      Dom.onSubmit( Dom.get( "two-factor-step-form" ) , this.onCode.bind( this ) );
    }
    Dom.get( "two-factor-step-code" ).focus();
  },

  async onCode( event ) {
    event.preventDefault();
    const input = Dom.get( "two-factor-step-code" );
    try {
      await Api.finishSignIn( this.challenge , input.value );
      // replace, not assign: a login link should not stay in the back button.
      window.location.replace( "/" );
    } catch ( error ) {
      if ( error.message === "challenge_invalid" ) {
        window.location.replace( "/?login=expired" );
        return;
      }
      input.value = "";
      input.focus();
      App.showError( error.message );
    }
  },

  // --- the panel ------------------------------------------------------------

  init( me ) {
    this.me = me;
    if ( !me.two_factor_enabled || me.auth !== "session" ) return;
    Dom.show( Dom.get( "two-factor-panel" ) , true );
    Dom.get( "two-factor-start-button" ).addEventListener( "click" , this.onStart.bind( this ) );
    Dom.onSubmit( Dom.get( "two-factor-confirm-form" ) , this.onConfirm.bind( this ) );
    Dom.onSubmit( Dom.get( "two-factor-disable-form" ) , this.onDisable.bind( this ) );
    Dom.get( "two-factor-recovery-copy" ).addEventListener( "click" , () => Dom.copy( Dom.get( "two-factor-recovery-codes" ) ) );
    Dom.get( "two-factor-recovery-download" ).addEventListener( "click" , () => {
      Dom.download( I18n.get( "two_factor.recovery_filename" ) , Dom.get( "two-factor-recovery-codes" ).textContent );
    } );
    Dom.get( "two-factor-secret-copy" ).addEventListener( "click" , () => Dom.copy( Dom.get( "two-factor-secret" ) ) );
    Dom.get( "two-factor-recovery-done" ).addEventListener( "click" , () => this.show( "status" ) );
    this.show( "status" );
  },

  // One of status, setup or recovery.
  show( step ) {
    const on = this.me.two_factor;
    const status = Dom.get( "two-factor-status" );
    Dom.text( status , I18n.get( on ? "two_factor.status_on" : "two_factor.status_off" ) );
    status.className = "badge " + ( on ? "text-bg-success" : "text-bg-secondary" );
    Dom.show( Dom.get( "two-factor-start-button" ) , step === "status" && !on );
    Dom.show( Dom.get( "two-factor-disable-form" ) , step === "status" && on );
    Dom.show( Dom.get( "two-factor-setup" ) , step === "setup" );
    Dom.show( Dom.get( "two-factor-recovery" ) , step === "recovery" );
  },

  async onStart() {
    try {
      const started = await Api.startTwoFactor();
      Dom.text( Dom.get( "two-factor-secret" ) , started.secret );
      Qr.draw( Dom.get( "two-factor-qr" ) , this.otpauthUri( started.secret ) );
      Dom.get( "two-factor-code" ).value = "";
      this.show( "setup" );
      Dom.get( "two-factor-code" ).focus();
    } catch ( error ) {
      App.showError( error.message );
    }
  },

  // What the app reads from the QR code. Built here rather than on the
  // server, because the app's name is in language.yaml.
  otpauthUri( secret ) {
    const issuer = I18n.get( "app.title" );
    const account = this.me.username || this.me.display_name;
    const label = encodeURIComponent( issuer ) + ":" + encodeURIComponent( account );
    return "otpauth://totp/" + label + "?secret=" + secret + "&issuer=" + encodeURIComponent( issuer )
      + "&algorithm=SHA1&digits=6&period=30";
  },

  async onConfirm( event ) {
    event.preventDefault();
    try {
      const confirmed = await Api.confirmTwoFactor( Dom.get( "two-factor-code" ).value );
      this.me.two_factor = true;
      Dom.text( Dom.get( "two-factor-recovery-codes" ) , confirmed.recovery_codes.join( "\n" ) );
      Dom.text( Dom.get( "two-factor-secret" ) , "" );
      this.show( "recovery" );
      Password.render();
    } catch ( error ) {
      App.showError( error.message );
    }
  },

  async onDisable( event ) {
    event.preventDefault();
    const input = Dom.get( "two-factor-disable-code" );
    try {
      await Api.disableTwoFactor( input.value );
      this.me.two_factor = false;
      input.value = "";
      this.show( "status" );
      Password.render();
      Dom.toast( I18n.get( "ui.saved" ) , "ok" );
    } catch ( error ) {
      App.showError( error.message );
    }
  },
};
