// Page logic for the account + admin screen this template ships with.
//
// Most projects will replace much of this file. What is worth keeping is the
// shape: load the language file, ask /api/me, then branch on
// authenticated/role. Do not keep a second client-side notion of "am I logged
// in" -- the server is the authority, and guessing is how the two drift apart.
// When the page needs to know again it asks again: see fresh.js, and the 401
// handling in api.js.
//
// New screens belong in their own file under /js/ with their own init(),
// rather than being appended here until this becomes the monolith the rest of
// the project is organised to avoid.

const App = {
  currentUser: null,

  async init() {
    try {
      await I18n.load();
      I18n.apply();
    } catch ( error ) {
      // Without the language file every label is blank, so say something in
      // the one place that can afford a hardcoded string.
      Dom.text( Dom.get( "error-banner" ) , "Could not load language file." );
      Dom.show( Dom.get( "error-banner" ) , true );
    }

    Theme.watchToggle( Dom.get( "theme-toggle" ) );
    Dom.all( "input[type=password]" ).forEach( ( input ) => Dom.revealable( input ) );
    // Not a plain #main link: the hash is which screen is showing.
    Dom.get( "skip-link" ).addEventListener( "click" , ( event ) => {
      event.preventDefault();
      Dom.get( "main" ).focus();
    } );

    let me = { authenticated: false };
    try {
      me = await Api.me();
    } catch ( error ) {
      this.showError( I18n.get( "errors.network" ) );
    }

    this.currentUser = me.authenticated ? me : null;
    Dom.show( Dom.get( "main" ) , true );

    const launchCredential = Install.takeLaunchCredential();
    if ( launchCredential !== "" && !me.authenticated && Install.standalone() ) {
      if ( await Install.signInFromLaunch( launchCredential ) ) return;
    }

    if ( this.loginCredential() !== "" ) {
      this.renderLoginConfirm( me );
      return;
    }
    if ( Join.credential() !== "" ) {
      await Join.init( me );
      return;
    }
    if ( !me.authenticated ) {
      this.renderSignedOut();
      return;
    }
    await this.renderSignedIn( me );
  },

  renderSignedOut() {
    Dom.show( Dom.get( "signed-out" ) , true );
    // A failed login lands here with ?login=invalid rather than explaining
    // what was wrong with the link -- see routes/auth.go.
    const params = new URLSearchParams( window.location.search );
    if ( params.get( "login" ) === "invalid" ) {
      const banner = Dom.get( "invalid-link" );
      if ( I18n.get( "signed_out.invalid_link" ) !== "" ) Dom.show( banner , true );
    }
    if ( params.get( "login" ) === "expired" ) {
      Dom.show( Dom.get( "sign-in-expired" ) , I18n.get( "signed_out.sign_in_expired" ) !== "" );
    }
    if ( params.get( "login" ) === "ended" ) {
      Dom.show( Dom.get( "session-ended" ) , I18n.get( "signed_out.session_ended" ) !== "" );
    }
    Install.initPaste();
    Password.initLogin();
  },

  // A login link is /login/<credential>, and the server answers it with this
  // page. Nothing has been redeemed at that point.
  loginCredential() {
    const prefix = "/login/";
    const path = window.location.pathname;
    if ( path.indexOf( prefix ) !== 0 ) return "";
    try {
      return decodeURIComponent( path.slice( prefix.length ) ).replace( /\/+$/ , "" );
    } catch ( error ) {
      return "";
    }
  },

  // Opening a login link only shows this. The link is spent by the POST the
  // button sends, so a chat app's link preview or a mail scanner fetching the
  // URL cannot use it up, and someone already signed in is told they are
  // about to switch accounts rather than being switched silently.
  renderLoginConfirm( me ) {
    Dom.show( Dom.get( "login-confirm" ) , true );
    if ( me.authenticated ) {
      const warning = I18n.get( "login_confirm.switch_warning" );
      if ( warning !== "" ) {
        const box = Dom.get( "login-switch-warning" );
        Dom.text( box , warning.replace( "{name}" , me.display_name ) );
        Dom.show( box , true );
      }
    }

    const button = Dom.get( "login-confirm-button" );
    button.addEventListener( "click" , async () => {
      button.disabled = true;
      try {
        const result = await Api.login( this.loginCredential() );
        if ( result.two_factor ) {
          TwoFactor.ask( result.challenge );
          return;
        }
        // replace, not assign: the link should not stay in the back button.
        window.location.replace( "/" );
      } catch ( error ) {
        if ( error.status === 400 ) {
          window.location.replace( "/?login=invalid" );
          return;
        }
        // Anything else (rate limited, network) leaves the link unspent,
        // so let them try again.
        button.disabled = false;
        this.showError( error.message );
      }
    } );
  },

  // Says so on every screen, so nobody wonders why a change was refused and
  // the owner, whom the mode lets through, cannot leave it on by accident.
  showMaintenance( me ) {
    const banner = Dom.get( "maintenance-banner" );
    const on = me.maintenance === "read_only" || me.maintenance === "full";
    if ( on ) Dom.text( banner , I18n.get( "maintenance." + me.maintenance + "_banner" ) );
    Dom.show( banner , on );
  },

  // What the owner wants everyone to read. Dismissing it is remembered against
  // its text, so the next message shows up however the last one went.
  showAnnouncement( me ) {
    const text = me.announcement || "";
    let dismissed = "";
    try {
      dismissed = window.localStorage.getItem( "announcement-dismissed" ) || "";
    } catch ( error ) { /* storage blocked: it comes back on the next load */ }
    Dom.text( Dom.get( "announcement-text" ) , text );
    Dom.show( Dom.get( "announcement-banner" ) , text !== "" && text !== dismissed );
  },

  onDismissAnnouncement() {
    Dom.show( Dom.get( "announcement-banner" ) , false );
    try {
      window.localStorage.setItem( "announcement-dismissed" , Dom.get( "announcement-text" ).textContent );
    } catch ( error ) { /* storage blocked: it comes back on the next load */ }
  },

  async renderSignedIn( me ) {
    Dom.show( Dom.get( "app-loading" ) , true );
    Dom.show( Dom.get( "signed-in" ) , true );
    this.showMaintenance( me );
    this.showAnnouncement( me );
    Dom.get( "announcement-dismiss" ).addEventListener( "click" , () => this.onDismissAnnouncement() );
    Dom.show( Dom.get( "app-nav" ) , true );
    this.labelAccount();
    Theme.render( Dom.get( "theme-picker" ) );
    Dom.get( "display-name" ).value = me.display_name;

    Dom.onSubmit( Dom.get( "rename-form" ) , this.onRename.bind( this ) );
    Dom.get( "logout-button" ).addEventListener( "click" , this.onLogout.bind( this ) );
    Dom.get( "my-link-button" ).addEventListener( "click" , this.onMyLoginLink.bind( this ) );
    Dom.get( "my-link-copy-button" ).addEventListener( "click" , () => Dom.copy( Dom.get( "my-link-value" ) ) );
    Qr.toggle( Dom.get( "my-link-qr-button" ) , Dom.get( "my-link-qr" ) , Dom.get( "my-link-value" ) );

    // Each screen owns its own file and its own init(). This is the one line
    // that knows the API keys screen exists.
    Track.init( me );
    Pin.init( me );
    Password.init( me );
    TwoFactor.init( me );
    Fresh.init( me );
    // Side by side: the wait is the slowest screen, not all of them added up.
    Install.init();
    Sounds.init();
    const loading = [ Keys.init( me ) , Sessions.init() , Files.init( me ) , Notifications.init( me ) , Apps.init() , Groups.init( me ) , Inbox.init() ];

    if ( me.role === "admin" ) {
      Dom.show( Dom.get( "admin-panel" ) , true );
      Dom.onSubmit( Dom.get( "create-user-form" ) , this.onCreateUser.bind( this ) );
      Dom.get( "copy-link-button" ).addEventListener( "click" , this.onCopyLink.bind( this ) );
      Qr.toggle( Dom.get( "login-link-qr-button" ) , Dom.get( "login-link-qr" ) , Dom.get( "login-link-value" ) );
      Dom.get( "users-search" ).addEventListener( "input" , () => {
        window.clearTimeout( this.searchTimer );
        this.searchTimer = window.setTimeout( () => this.refreshUsers() , 300 );
      } );
      Dom.get( "user-sessions-close" ).addEventListener( "click" , () => Sessions.closeFor() );
      // Only the owner gets the Logs, Jobs, Webhooks and Settings screens; each init
      // checks is_owner.
      loading.push( this.refreshUsers() , Invites.init( me ) , Logs.init( me ) , Jobs.init( me ) , Webhooks.init( me ) , Settings.init( me ) );
      const version = I18n.get( "nav.version" );
      if ( version !== "" ) {
        Dom.text( Dom.get( "sidebar-version" ) , version.replace( "{version}" , me.version ) );
        Dom.show( Dom.get( "sidebar-version" ) , true );
      }
    }

    // allSettled, not all: Nav.init has to run whatever else went wrong, or
    // one screen's failure would leave no screen showing at all.
    const results = await Promise.allSettled( loading );
    results.forEach( ( result ) => {
      if ( result.status === "rejected" ) this.showError( result.reason.message );
    } );
    Dom.show( Dom.get( "app-loading" ) , false );

    // Last, so the sidebar offers exactly the screens the lines above un-hid.
    Nav.init();
  },

  async onRename( event ) {
    event.preventDefault();
    const value = Dom.get( "display-name" ).value.trim();
    const previous = this.currentUser.display_name;
    if ( value === previous ) return;
    try {
      await this.applyRename( value , previous );
    } catch ( error ) {
      this.showError( error.message );
      return;
    }
    // Let go of the field, so the next Ctrl+Z undoes the rename rather than
    // the typing.
    Undo.saved( event.target );
    // The server-backed undo example: both directions go through the API, so
    // Ctrl+Z puts the old name back on the account, not just on the screen.
    // Each says which name it expects to find, so a rename made in another
    // tab since is refused (409) rather than overwritten.
    Undo.record( {
      label: I18n.get( "undo.rename" ),
      toast: true,
      undo: () => this.applyRename( previous , value ),
      redo: () => this.applyRename( value , previous ),
    } );
  },

  async applyRename( value , expect ) {
    await Api.rename( value , expect );
    this.currentUser.display_name = value;
    Dom.get( "display-name" ).value = value;
    this.labelAccount();
  },

  // The sidebar's Account entry names who is signed in on its second line.
  labelAccount() {
    const user = this.currentUser;
    Dom.text( Dom.get( "sidebar-user" ) , user.display_name + " (" + user.role + ")" );
  },

  // A fresh one-time link for this account, to open on another device. The
  // server only allows it from a browser session, never an API key.
  async onMyLoginLink() {
    try {
      const issued = await Api.createMyLoginLink();
      Dom.text( Dom.get( "my-link-value" ) , window.location.origin + issued.login_path );
      Qr.hide( Dom.get( "my-link-qr" ) );
      Dom.show( Dom.get( "my-link-box" ) , true );
    } catch ( error ) {
      this.showError( error.message );
    }
  },

  async onLogout() {
    await Notifications.unsubscribe();
    try {
      await Api.logout();
    } catch ( error ) {
      // Even if the call failed, reloading lands on the signed-out page,
      // which is the honest state to show.
    }
    window.location.href = "/";
  },

  async onCreateUser( event ) {
    event.preventDefault();
    const name = Dom.get( "new-name" ).value.trim();
    const role = Dom.get( "new-role" ).value;
    try {
      const created = await Api.createUser( name , role );
      this.showLoginLink( created.login_path );
      Dom.get( "new-name" ).value = "";
      await this.refreshUsers();
    } catch ( error ) {
      this.showError( error.message );
    }
  },

  // The server returns a path, not a full URL: behind a reverse proxy it does
  // not reliably know its own public origin, whereas the browser always does.
  showLoginLink( loginPath ) {
    Dom.text( Dom.get( "login-link-value" ) , window.location.origin + loginPath );
    Qr.hide( Dom.get( "login-link-qr" ) );
    Dom.show( Dom.get( "login-link-box" ) , true );
  },

  async onCopyLink() {
    await Dom.copy( Dom.get( "login-link-value" ) );
  },

  // A name or a role shows on the other admin screens too: All keys lists
  // whose each key is, and a link stops when its maker stops being an admin.
  async refreshAfterUserChange() {
    await App.refreshUsers();
    if ( App.currentUser.api_keys_enabled ) await Keys.refreshAll();
    if ( App.currentUser.invite_links_enabled !== false ) await Invites.refresh();
  },

  async refreshUsers() {
    const body = Dom.get( "users-table" ).querySelector( "tbody" );
    const search = Dom.get( "users-search" ).value.trim();
    await Pager.load( "users-table" , "users" , ( offset ) => Api.listUsers( offset , search ) , function ( user ) {
      const statusKey = user.disabled ? "admin.status_disabled" : "admin.status_active";
      const statusTone = user.disabled ? "secondary" : "success";

      const reissueButton = Dom.el( "button" , {
        class: "btn btn-sm btn-outline-secondary",
        text: I18n.get( "admin.reissue_button" ),
        on: { click: async function () {
          try {
            const issued = await Api.reissueLogin( user.id );
            App.showLoginLink( issued.login_path );
          } catch ( error ) { App.showError( error.message ); }
        } },
      } );

      // The server is the authority on all of these; the rules below only
      // decide which buttons it would refuse, so they are not offered. Your
      // own row and the owner's never get revoke, disable, or delete.
      const isSelf = user.id === App.currentUser.id;
      const isProtected = isSelf || user.owner;

      // Revoking is for "someone else may have this account's credentials":
      // it ends every session, unused login link, and API key, and leaves the
      // account enabled. Not offered on your own row -- the server refuses
      // that, since it would sign you out with no way back in.
      const revokeButton = isProtected ? null : Dom.el( "button" , {
        class: "btn btn-sm btn-outline-danger",
        text: I18n.get( "admin.revoke_button" ),
        on: { click: async function () {
          const question = I18n.get( "admin.revoke_confirm" ).replace( "{name}" , user.display_name );
          if ( !( await Dom.confirm( question ) ) ) return;
          try {
            await Api.revokeAccess( user.id );
            if ( App.currentUser.api_keys_enabled ) await Keys.refreshAll();
          } catch ( error ) { App.showError( error.message ); }
        } },
      } );

      // Disabling asks first and is not undoable, like a revoke: it ends their
      // sessions and unused links, and enabling does not bring those back.
      const toggleButton = isProtected ? null : Dom.el( "button" , {
        class: "btn btn-sm btn-outline-secondary",
        text: I18n.get( user.disabled ? "admin.enable_button" : "admin.disable_button" ),
        on: { click: async function () {
          if ( !user.disabled ) {
            const question = I18n.get( "admin.disable_confirm" ).replace( "{name}" , user.display_name );
            if ( !( await Dom.confirm( question ) ) ) return;
          }
          try {
            await Api.setDisabled( user.id , !user.disabled );
            await App.refreshUsers();
            Dom.toast( I18n.get( user.disabled ? "admin.enabled_toast" : "admin.disabled_toast" ).replace( "{name}" , user.display_name ) , "ok" );
          } catch ( error ) { App.showError( error.message ); }
        } },
      } );

      // Who may change what follows the delete rules, but any admin may make
      // another. Both ask first and neither can undo: becoming an admin ends
      // their sessions, which nothing brings back.
      const mayManage = user.role !== "admin" || App.currentUser.is_owner;
      const newRole = user.role === "admin" ? "user" : "admin";
      const roleButton = isProtected || !mayManage ? null : Dom.el( "button" , {
        class: "btn btn-sm btn-outline-secondary",
        text: I18n.get( "admin.make_" + newRole + "_button" ),
        on: { click: async function () {
          const question = I18n.get( "admin.make_" + newRole + "_confirm" ).replace( "{name}" , () => user.display_name );
          if ( !( await Dom.confirm( question ) ) ) return;
          try {
            await Api.setUserRole( user.id , newRole );
            await App.refreshAfterUserChange();
            Dom.toast( I18n.get( "admin.role_changed_toast" ).replace( "{name}" , () => user.display_name ).replace( "{role}" , newRole ) , "ok" );
          } catch ( error ) { App.showError( error.message ); }
        } },
      } );

      // Your own name is on the Account screen. It edits in place, and is
      // built with textContent: a display name is user-controlled input.
      const nameCell = isSelf || !mayManage ? Dom.el( "span" , { text: user.display_name } ) : Dom.editable( user.display_name , {
        label: I18n.get( "admin.table_name" ),
        maxLength: 80,
        save: async function ( value ) {
          const previous = user.display_name;
          await Api.renameUser( user.id , value , previous );
          user.display_name = value;
          Undo.record( {
            label: I18n.get( "undo.rename" ),
            toast: true,
            undo: async () => { await Api.renameUser( user.id , previous , value ); await App.refreshAfterUserChange(); },
            redo: async () => { await Api.renameUser( user.id , value , previous ); await App.refreshAfterUserChange(); },
          } );
        },
      } );

      // Deleting removes the account and everything it held, for good. Any
      // admin may delete a user; only the owner may delete another admin.
      const canDelete = !isProtected && ( user.role !== "admin" || App.currentUser.is_owner );
      const deleteButton = !canDelete ? null : Dom.el( "button" , {
        class: "btn btn-sm btn-outline-danger",
        text: I18n.get( "admin.delete_button" ),
        on: { click: async function () {
          const question = I18n.get( "admin.delete_confirm" ).replace( "{name}" , user.display_name );
          if ( !( await Dom.confirm( question ) ) ) return;
          try {
            await Api.deleteUser( user.id );
            await App.refreshUsers();
            if ( App.currentUser.api_keys_enabled ) await Keys.refreshAll();
          } catch ( error ) { App.showError( error.message ); }
        } },
      } );

      // Only for someone who lost their phone and recovery codes. Who may
      // reset whom follows the delete rules; the owner's is shell-only.
      const canReset = user.two_factor && !isProtected && ( user.role !== "admin" || App.currentUser.is_owner );
      const resetButton = !canReset ? null : Dom.el( "button" , {
        class: "btn btn-sm btn-outline-danger",
        text: I18n.get( "admin.reset_two_factor_button" ),
        on: { click: async function () {
          const question = I18n.get( "admin.reset_two_factor_confirm" ).replace( "{name}" , user.display_name );
          if ( !( await Dom.confirm( question ) ) ) return;
          try {
            await Api.resetTwoFactor( user.id );
            await App.refreshUsers();
          } catch ( error ) { App.showError( error.message ); }
        } },
      } );

      // Where they are signed in. The owner's are the owner's own, which the
      // server would refuse.
      const sessionsButton = user.owner && !App.currentUser.is_owner ? null : Dom.el( "button" , {
        class: "btn btn-sm btn-outline-secondary",
        text: I18n.get( "admin.sessions_button" ),
        on: { click: () => Sessions.showFor( user ) },
      } );

      // The owner's per-account password switch. Everyone else gets a 404
      // from the server, so it is not offered.
      const canBlock = App.currentUser.is_owner && App.currentUser.passwords_enabled;
      const passwordButton = !canBlock ? null : Dom.el( "button" , {
        class: "btn btn-sm btn-outline-secondary",
        text: I18n.get( user.password_blocked ? "admin.allow_password_button" : "admin.block_password_button" ),
        on: { click: async function () {
          try {
            await Api.setPasswordAccess( user.id , user.password_blocked );
            await App.refreshUsers();
          } catch ( error ) { App.showError( error.message ); }
        } },
      } );

      const ownerLabel = I18n.get( "admin.owner_label" );
      const roleText = user.owner && ownerLabel !== "" ? user.role + " (" + ownerLabel + ")" : user.role;

      // Built with createElement + textContent, never an HTML string: a
      // display name is user-controlled input.
      body.appendChild( Dom.el( "tr" , { children: [
        Dom.el( "td" , { children: [ nameCell ] } ),
        Dom.el( "td" , { text: roleText } ),
        Dom.el( "td" , { children: [ Dom.badge( I18n.get( statusKey ) , statusTone ) ] } ),
        Dom.el( "td" , { children: [
          Dom.el( "div" , { class: "row-actions" , children: [ reissueButton , sessionsButton , passwordButton , roleButton , resetButton , revokeButton , toggleButton , deleteButton ].filter( Boolean ) } ),
        ] } ),
      ] } ) );
    } );
  },

  // message may be an error code the server answered with (pin_wrong,
  // invite_link_full, ...); language.yaml's errors section words those.
  showError( message ) {
    const banner = Dom.get( "error-banner" );
    const worded = message ? I18n.get( "errors." + message ) : "";
    Dom.text( banner , worded || message || I18n.get( "errors.generic" ) );
    // Long enough to copy a reference down.
    Dom.flash( banner , 12000 );
    // It sits at the top of the screen, which may be scrolled well past.
    banner.scrollIntoView( { block: "nearest" } );
  },
};

document.addEventListener( "DOMContentLoaded" , function () {
  App.init();
} );
