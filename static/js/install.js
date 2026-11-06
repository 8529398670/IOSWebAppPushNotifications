// Getting iPB onto a Home Screen, and signed in once it is there.
//
// iOS gives a Home Screen app cookies of its own. The ones tested so far arrive
// with Safari's sign-in copied over, but an install link's manifest also carries
// a one-time credential in start_url, for an iOS that does not. start_url is
// kept for good, so every launch arrives with it: it is taken out of the address
// straight away, and used only if this launch has no session.
const Install = {
  standalone() {
    return window.matchMedia( "(display-mode: standalone)" ).matches || window.navigator.standalone === true;
  },

  // An iPad asks to be treated as a Mac, but still has a touch screen.
  onIOS() {
    return /iPhone|iPad|iPod/.test( window.navigator.userAgent ) ||
      ( window.navigator.platform === "MacIntel" && window.navigator.maxTouchPoints > 1 );
  },

  onInstallLink() {
    return window.location.pathname.indexOf( "/i/" ) === 0;
  },

  takeLaunchCredential() {
    const params = new URLSearchParams( window.location.search );
    const credential = params.get( "credential" ) || "";
    if ( credential !== "" ) {
      params.delete( "credential" );
      const rest = params.toString();
      window.history.replaceState( null , "" , window.location.pathname + ( rest ? "?" + rest : "" ) + window.location.hash );
    }
    return credential;
  },

  // Answers true when it has taken over the page.
  async signInFromLaunch( credential ) {
    try {
      const result = await Api.login( credential );
      if ( result.two_factor ) {
        TwoFactor.ask( result.challenge );
        return true;
      }
      window.location.replace( "/" );
    } catch ( error ) {
      // Spent or expired, which is what a later launch's link always is.
      return false;
    }
    return true;
  },

  // The signed-out screen's box. A pasted link goes where it would have gone if
  // opened, so its confirmation and two-factor steps all still happen.
  initPaste() {
    Dom.onSubmit( Dom.get( "paste-link-form" ) , async ( event ) => {
      event.preventDefault();
      const value = Dom.get( "paste-link" ).value.trim();
      const found = value.match( /\/(login|join)\/[^\s]+/ );
      if ( !found ) {
        App.showError( I18n.get( "signed_out.paste_invalid" ) );
        return;
      }
      window.location.assign( found[ 0 ] );
    } );
  },

  init() {
    const show = this.onIOS() && !this.standalone();
    Dom.show( Dom.get( "install-card" ) , show );
    if ( !show ) return;
    const linked = this.onInstallLink();
    Dom.show( Dom.get( "install-prepare" ) , !linked );
    Dom.show( Dom.get( "install-steps" ) , linked );
    const button = Dom.get( "install-prepare-button" );
    button.addEventListener( "click" , () => Dom.busy( button , async () => {
      try {
        const link = await Api.post( "/api/push/install-link" );
        window.location.assign( link.install_path );
      } catch ( error ) {
        App.showError( error.message );
      }
    } ) );
  },
};
