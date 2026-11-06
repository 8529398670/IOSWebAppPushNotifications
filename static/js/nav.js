// The sidebar: which signed-in screen is showing.
//
// Every screen is a <section class="view" data-view="name"> in index.html and
// a sidebar link to #name. The URL hash is the only state -- back, forward,
// reload and a pasted link all land on the same screen, with no router.
//
// Whether a screen exists for this user is not decided here. The screen's own
// file un-hides its section (Keys.init shows the API keys panel, and only if
// the server has them switched on); Nav only offers what was un-hidden. So
// app.js calls Nav.init() last, once every screen has had its say.
const Nav = {
  fallback: "inbox",
  // Matches Bootstrap's lg breakpoint, where offcanvas-lg becomes a column.
  wide: window.matchMedia( "(min-width: 992px)" ),
  // Collapsed-or-not is a per-browser convenience, like the theme.
  storageKey: "sidebar-collapsed",

  init() {
    Dom.all( "[data-nav]" ).forEach( ( link ) => {
      Dom.show( link , this.available( link.getAttribute( "data-nav" ) ) );
      link.addEventListener( "click" , () => this.closeSidebar() );
    } );
    // A group heading with nothing left under it goes too.
    Dom.all( ".sidebar-group" ).forEach( function ( group ) {
      Dom.show( group , Dom.all( "[data-nav]:not([hidden])" , group ).length > 0 );
    } );
    // Before the sidebar appears, so a collapsed one never flashes open.
    this.setCollapsed( this.savedCollapsed() );
    Dom.show( Dom.get( "sidebar" ) , true );
    const toggle = Dom.get( "sidebar-toggle" );
    toggle.addEventListener( "click" , () => this.toggleSidebar() );
    Dom.show( toggle , true );

    // Moving between screens is not an undo step: Back and Forward already
    // are that, and an undo that only changed the screen would get in the way
    // of undoing what was done on it.
    window.addEventListener( "hashchange" , () => this.render() );
    this.render();
  },

  // Undo uses this to go back to the screen an action happened on.
  show( name ) {
    window.location.hash = "#" + name;
    this.render();
  },

  available( name ) {
    const view = document.querySelector( '.view[data-view="' + name + '"]' );
    return Boolean( view ) && !view.hidden;
  },

  // A hash naming a screen this user does not have (an admin link opened by a
  // non-admin, a typo) shows the inbox rather than nothing.
  current() {
    const name = window.location.hash.replace( /^#/ , "" );
    return this.available( name ) ? name : this.fallback;
  },

  render() {
    const name = this.current();
    Track.nav( name );
    Dom.all( ".view" ).forEach( function ( view ) {
      view.classList.toggle( "view-active" , view.getAttribute( "data-view" ) === name );
    } );
    Dom.all( "[data-nav]" ).forEach( function ( link ) {
      const active = link.getAttribute( "data-nav" ) === name;
      link.classList.toggle( "active" , active );
      if ( active ) link.setAttribute( "aria-current" , "page" );
      else link.removeAttribute( "aria-current" );
    } );
    window.scrollTo( 0 , 0 );
    this.announce( name );
  },

  // Changing screen reloads nothing, so nothing tells a screen reader or the
  // browser's tab that anything happened. The title names the screen, and the
  // focus moves to its heading, except on load, when it belongs to the page.
  announce( name ) {
    const heading = document.querySelector( '.view[data-view="' + name + '"] h2' );
    if ( !heading ) return;
    const title = I18n.get( "nav.page_title" );
    if ( title !== "" ) document.title = title.replace( "{screen}" , heading.textContent ).replace( "{app}" , I18n.get( "app.title" ) );
    const moved = this.shown !== undefined && this.shown !== name;
    this.shown = name;
    if ( !moved ) return;
    heading.setAttribute( "tabindex" , "-1" );
    heading.focus( { preventScroll: true } );
  },

  // The menu button: on a wide screen it folds the sidebar column away and
  // back; on a phone it slides the panel in and out. Only the folding is
  // undoable: the phone panel is gone again as soon as a screen is picked.
  toggleSidebar() {
    if ( this.wide.matches ) {
      const collapsed = !document.documentElement.classList.contains( "sidebar-collapsed" );
      Undo.run( {
        label: I18n.get( "undo.sidebar" ),
        screen: null,
        do: () => this.saveCollapsed( collapsed ),
        undo: () => this.saveCollapsed( !collapsed ),
      } );
    } else if ( window.bootstrap ) {
      bootstrap.Offcanvas.getOrCreateInstance( Dom.get( "sidebar" ) ).toggle();
    }
  },

  setCollapsed( collapsed ) {
    document.documentElement.classList.toggle( "sidebar-collapsed" , collapsed );
    Dom.get( "sidebar-toggle" ).setAttribute( "aria-expanded" , String( !collapsed ) );
  },

  saveCollapsed( collapsed ) {
    this.setCollapsed( collapsed );
    try {
      if ( collapsed ) window.localStorage.setItem( this.storageKey , "1" );
      else window.localStorage.removeItem( this.storageKey );
    } catch ( error ) { /* storage blocked: it just is not remembered */ }
  },

  savedCollapsed() {
    try {
      return window.localStorage.getItem( this.storageKey ) === "1";
    } catch ( error ) {
      return false;
    }
  },

  // On a phone the sidebar is a slide-in panel; picking a screen closes it,
  // including the one already showing (which changes no hash).
  closeSidebar() {
    const panel = window.bootstrap && bootstrap.Offcanvas.getInstance( Dom.get( "sidebar" ) );
    if ( panel ) panel.hide();
  },
};
