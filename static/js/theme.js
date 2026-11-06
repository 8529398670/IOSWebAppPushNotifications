// How the page looks: light, dark, or one of a few ready-made themes.
//
// Light is the default and stays it -- never the OS setting. Picking another
// theme is remembered in this browser (localStorage) only; nothing goes to
// the server. Move it onto the account if a theme should follow a person to
// every device.
//
// Dark is Bootstrap's own dark mode (<html data-bs-theme="dark">). Light is
// the attribute being absent, and Bootstrap's colour-mode script, which would
// follow prefers-color-scheme, is deliberately not included.
//
// This file is loaded in <head>, before the stylesheet's first paint, so a
// saved dark theme never flashes light on the way in.
const Theme = {
  storageKey: "theme",
  // What redraws when the theme changes: the picker and the navbar button.
  onChange: [],

  // Each preset sets the mode plus, optionally, its own colours. Field ->
  // custom property in style.css, which hands them on to Bootstrap: accent ->
  // --app-accent, background -> --app-bg, surface -> --app-surface. Names
  // come from language.yaml (theme.preset_<key>).
  presets: [
    { key: "light" , mode: "light" },
    { key: "dark" , mode: "dark" },
    { key: "ocean" , mode: "light" , accent: "#0b7285" , background: "#eef6f8" , surface: "#ffffff" },
    { key: "forest" , mode: "light" , accent: "#2b8a3e" , background: "#f1f6ef" , surface: "#ffffff" },
    { key: "sepia" , mode: "light" , accent: "#9c5a1c" , background: "#f6f0e4" , surface: "#fbf7ef" },
    { key: "grape" , mode: "light" , accent: "#7048c8" , background: "#f5f2fc" , surface: "#ffffff" },
    { key: "pink" , mode: "light" , accent: "#c2255c" , background: "#fdf0f5" , surface: "#ffffff" },
    // Wright State University: Green on Off White, and Gold on Black with Dark Green panels.
    { key: "wsu" , mode: "light" , accent: "#046a38" , background: "#f2f1f0" , surface: "#ffffff" },
    { key: "midnight" , mode: "dark" , accent: "#8c7cff" , background: "#0e1020" , surface: "#171a30" },
    { key: "slate" , mode: "dark" , accent: "#4fb3a9" , background: "#15191e" , surface: "#1d232a" },
    { key: "dark_pink" , mode: "dark" , accent: "#f06595" , background: "#1f0d16" , surface: "#2a1220" },
    { key: "wsu_dark" , mode: "dark" , accent: "#cba052" , background: "#101820" , surface: "#00482b" },
  ],

  vars: { accent: "--app-accent" , background: "--app-bg" , surface: "--app-surface" },

  current: "light",

  find( key ) {
    return this.presets.find( function ( preset ) { return preset.key === key; } ) || this.presets[ 0 ];
  },

  restore() {
    let saved = "";
    try {
      saved = window.localStorage.getItem( this.storageKey ) || "";
    } catch ( error ) {
      // Storage blocked (private window, previews): stay light.
    }
    this.current = this.find( saved ).key;
    this.apply( this.find( this.current ) );
  },

  set( key ) {
    this.current = this.find( key ).key;
    try {
      if ( this.current === "light" ) window.localStorage.removeItem( this.storageKey );
      else window.localStorage.setItem( this.storageKey , this.current );
    } catch ( error ) {
      // Not remembered for next time, but still applied now.
    }
    this.apply( this.find( this.current ) );
  },

  apply( preset ) {
    const root = document.documentElement;
    if ( preset.mode === "dark" ) root.setAttribute( "data-bs-theme" , "dark" );
    else root.removeAttribute( "data-bs-theme" );
    Object.keys( this.vars ).forEach( ( field ) => {
      if ( preset[ field ] ) root.style.setProperty( this.vars[ field ] , preset[ field ] );
      else root.style.removeProperty( this.vars[ field ] );
    } );
    // Text on the accent has to stay readable whatever the accent is.
    if ( preset.accent ) root.style.setProperty( "--app-accent-fg" , this.contrast( preset.accent , "#ffffff" ) >= this.contrast( preset.accent , "#0b0d10" ) ? "#ffffff" : "#0b0d10" );
    else root.style.removeProperty( "--app-accent-fg" );
    // A custom page colour gets borders drawn from it rather than the mode's.
    if ( preset.background ) root.style.setProperty( "--app-border" , "color-mix(in srgb, var(--bs-body-color) 14%, " + preset.background + ")" );
    else root.style.removeProperty( "--app-border" );
  },

  // Picking is undoable, and quick picks merge into one step.
  pick( key ) {
    const previous = this.current;
    if ( previous === key ) return;
    const choose = ( chosen ) => {
      this.set( chosen );
      this.onChange.forEach( ( listener ) => listener() );
    };
    Undo.run( {
      label: I18n.get( "undo.theme" ),
      merge: "theme",
      screen: null,
      do: () => choose( key ),
      undo: () => choose( previous ),
    } );
  },

  // The button in the navbar: light or dark from anywhere, signed in or not.
  // The Appearance card has the rest. Dark from any light theme, light from any
  // dark one.
  watchToggle( button ) {
    const icon = button.querySelector( "i" );
    const update = () => {
      const dark = this.find( this.current ).mode === "dark";
      icon.className = "bi " + ( dark ? "bi-sun" : "bi-moon-stars" );
    };
    button.addEventListener( "click" , () => this.pick( this.find( this.current ).mode === "dark" ? "light" : "dark" ) );
    this.onChange.push( update );
    update();
  },

  // The picker on the Appearance card: one button per preset, drawn in its
  // own colours. summary, if given, is kept showing the current theme's name.
  render( root , summary ) {
    Dom.clear( root );
    const update = () => {
      Dom.all( "button" , root ).forEach( ( button ) => {
        button.classList.toggle( "active" , button.getAttribute( "data-theme-key" ) === this.current );
        button.setAttribute( "aria-pressed" , button.getAttribute( "data-theme-key" ) === this.current ? "true" : "false" );
      } );
      if ( summary ) Dom.text( summary , I18n.get( "theme.preset_" + this.current ) );
    };
    this.presets.forEach( ( preset ) => {
      const swatch = Dom.el( "span" , { class: "theme-swatch" + ( preset.mode === "dark" ? " theme-swatch-dark" : "" ) } );
      if ( preset.background ) swatch.style.setProperty( "--swatch-bg" , preset.background );
      if ( preset.accent ) swatch.style.setProperty( "--swatch-accent" , preset.accent );
      const button = Dom.el( "button" , {
        class: "btn btn-outline-secondary theme-choice",
        attrs: { type: "button" , "data-theme-key": preset.key },
        children: [ swatch , Dom.el( "span" , { text: I18n.get( "theme.preset_" + preset.key ) } ) ],
        on: { click: () => this.pick( preset.key ) },
      } );
      root.appendChild( button );
    } );
    this.onChange.push( update );
    update();
  },

  // Relative luminance (WCAG) of #rrggbb.
  luminance( hex ) {
    const channel = function ( offset ) {
      const value = parseInt( hex.slice( offset , offset + 2 ) , 16 ) / 255;
      return value <= 0.03928 ? value / 12.92 : Math.pow( ( value + 0.055 ) / 1.055 , 2.4 );
    };
    return 0.2126 * channel( 1 ) + 0.7152 * channel( 3 ) + 0.0722 * channel( 5 );
  },

  contrast( first , second ) {
    const a = this.luminance( first ) , b = this.luminance( second );
    return ( Math.max( a , b ) + 0.05 ) / ( Math.min( a , b ) + 0.05 );
  },
};

Theme.restore();
