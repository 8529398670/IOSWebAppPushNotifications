// The page an invite link opens: /join/<credential>.
//
// Three steps, and nothing is created until the last button press:
//
//   1. type your name;
//   2. "is one of these you?" -- accounts that joined through this same link
//      with a similar name, plus "no, I'm new". This step is shown even with
//      no matches, because a typo would otherwise use up a place;
//   3. the PIN, if the account you picked set one, then the two-factor code
//      if it has that on (see two_factor.js).
//
// Picking yourself is how the same person signs in on their next device, so
// a chat app's link preview fetching the URL does nothing: every step is a
// POST this page sends.
const Join = {
  me: null,
  link: null,
  typed: "",
  picked: null,

  credential() {
    const prefix = "/join/";
    const path = window.location.pathname;
    if ( path.indexOf( prefix ) !== 0 ) return "";
    try {
      return decodeURIComponent( path.slice( prefix.length ) ).replace( /\/+$/ , "" );
    } catch ( error ) {
      return "";
    }
  },

  async init( me ) {
    this.me = me;
    Dom.show( Dom.get( "join" ) , true );
    try {
      this.link = await Api.joinInfo( this.credential() );
    } catch ( error ) {
      this.invalid( error );
      return;
    }

    Dom.text( Dom.get( "join-heading" ) , I18n.get( "join.heading" ).replace( "{label}" , this.link.label ) );
    if ( me.authenticated ) {
      const warning = I18n.get( "join.switch_warning" );
      if ( warning !== "" ) {
        const box = Dom.get( "join-switch-warning" );
        Dom.text( box , warning.replace( "{name}" , me.display_name ) );
        Dom.show( box , true );
      }
    }

    Dom.onSubmit( Dom.get( "join-name-form" ) , this.onName.bind( this ) );
    Dom.get( "join-create-button" ).addEventListener( "click" , this.onCreate.bind( this ) );
    Dom.get( "join-back-button" ).addEventListener( "click" , this.step.bind( this , "name" ) );
    Dom.onSubmit( Dom.get( "join-pin-form" ) , this.onPin.bind( this ) );
    Dom.get( "join-pin-back-button" ).addEventListener( "click" , this.step.bind( this , "choose" ) );
    this.step( "name" );
  },

  // A dead link says so and offers nothing else; which way it is dead is not
  // something the server tells anyone.
  invalid( error ) {
    if ( error.status !== 404 ) {
      App.showError( error.message );
      return;
    }
    Dom.text( Dom.get( "join-heading" ) , I18n.get( "join.invalid_heading" ) );
    Dom.show( Dom.get( "join-invalid" ) , true );
    [ "join-name-step" , "join-choose" , "join-pin-step" , "join-switch-warning" ].forEach( function ( id ) {
      Dom.show( Dom.get( id ) , false );
    } );
  },

  step( name ) {
    Dom.show( Dom.get( "join-name-step" ) , name === "name" );
    Dom.show( Dom.get( "join-choose" ) , name === "choose" );
    Dom.show( Dom.get( "join-pin-step" ) , name === "pin" );
    if ( name === "name" ) Dom.get( "join-name" ).focus();
    if ( name === "pin" ) Dom.get( "join-pin" ).focus();
  },

  async onName( event ) {
    event.preventDefault();
    this.typed = Dom.get( "join-name" ).value.trim();
    if ( this.typed === "" ) return;
    let found;
    try {
      found = await Api.joinMatch( this.credential() , this.typed );
    } catch ( error ) {
      this.failed( error );
      return;
    }

    const list = Dom.get( "join-matches" );
    Dom.clear( list );
    found.matches.forEach( function ( user ) {
      const pinTag = user.has_pin && I18n.get( "join.has_pin" ) !== ""
        ? Dom.el( "span" , { class: "badge text-bg-secondary ms-2" , text: I18n.get( "join.has_pin" ) } )
        : null;
      list.appendChild( Dom.el( "div" , { class: "list-group-item d-flex justify-content-between align-items-center gap-2" , children: [
        Dom.el( "span" , { children: [ Dom.el( "strong" , { text: user.display_name } ) , pinTag ].filter( Boolean ) } ),
        Dom.el( "button" , {
          class: "btn btn-sm btn-outline-primary",
          text: I18n.get( "join.this_is_me" ),
          on: { click: function () { Join.onPick( user ); } },
        } ),
      ] } ) );
    } );

    const hasMatches = found.matches.length > 0;
    Dom.text( Dom.get( "join-choose-heading" ) , I18n.get( hasMatches ? "join.did_you_mean" : "join.no_match" ) );
    const createButton = Dom.get( "join-create-button" );
    Dom.text( createButton , I18n.get( hasMatches ? "join.create_new" : "join.create_first" ).replace( "{name}" , this.typed ) );
    Dom.show( createButton , found.can_create );
    Dom.show( Dom.get( "join-full" ) , !found.can_create && I18n.get( "join.full" ) !== "" );
    this.step( "choose" );
  },

  onPick( user ) {
    this.picked = user;
    if ( !user.has_pin ) {
      this.claim( "" );
      return;
    }
    Dom.text( Dom.get( "join-pin-prompt" ) , I18n.get( "join.pin_prompt" ).replace( "{name}" , user.display_name ) );
    Dom.get( "join-pin" ).value = "";
    this.step( "pin" );
  },

  onPin( event ) {
    event.preventDefault();
    return this.claim( Dom.get( "join-pin" ).value );
  },

  async claim( pin ) {
    try {
      const result = await Api.joinClaim( this.credential() , this.picked.id , pin );
      if ( result.two_factor ) {
        TwoFactor.ask( result.challenge );
        return;
      }
      this.done();
    } catch ( error ) {
      this.failed( error );
    }
  },

  async onCreate() {
    const button = Dom.get( "join-create-button" );
    button.disabled = true;
    try {
      await Api.joinCreate( this.credential() , this.typed );
      this.done();
    } catch ( error ) {
      button.disabled = false;
      this.failed( error );
    }
  },

  failed( error ) {
    if ( error.message === "invite_link_invalid" ) {
      this.invalid( error );
      return;
    }
    App.showError( error.message );
  },

  // replace, not assign: the link should not stay in the back button.
  done() {
    window.location.replace( "/" );
  },
};
