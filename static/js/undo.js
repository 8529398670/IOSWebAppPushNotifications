// Undo and redo for anything the person does on the page: Ctrl+Z (Cmd+Z on a
// Mac) steps back, Ctrl+Y or Ctrl+Shift+Z steps forward again. A toast with
// an Undo button does the same for anyone without a keyboard.
//
// A screen makes an action undoable by doing it through Undo.run:
//
//   Undo.run( { label: I18n.get( "undo.theme" ) ,
//               do: () => Theme.set( next ) ,
//               undo: () => Theme.set( previous ) } );
//
// or, when the change has already happened (a form that saved first), by
// handing over both directions with Undo.record( { label , undo , redo } ).
//
// Optional fields on either:
//   toast: true    -- say what happened, with an Undo button. For deletes and
//                     anything else the person cannot see change on screen.
//   merge: "theme" -- quick repeats of the same kind (clicking through five
//                     themes) fold into one step, so one Ctrl+Z gets back to
//                     where they started.
//   screen: null   -- do not go back to the screen it happened on.
//
// Each action remembers the screen it happened on. Undoing it from another
// screen goes back there first, so the person sees what was put back.
// Moving between screens is not itself recorded: that is the browser's Back.
//
// Steps may be async, so an undo can call the server through Api -- rename
// is the worked example in app.js. Each step awaits before the next key is
// taken, so holding Ctrl+Z never runs two at once.
//
// While a text field has focus the shortcuts are left alone: the browser's
// own undo of what was typed there is what anyone expects. A form that has
// saved calls Undo.saved( form ) to let go of the focus, so the next Ctrl+Z
// undoes the save rather than the typing.
//
// History lives in memory only. A reload starts it fresh, which is also what
// keeps it from crossing a sign-out (logout reloads the page).
const Undo = {
  limit: 100,
  // Repeats of the same merge key closer together than this are one step.
  mergeWindow: 1500,
  done: [],
  undone: [],
  busy: false,
  // Set while a step runs, so UI code the step triggers does not record the
  // step a second time.
  replaying: false,

  async run( action ) {
    await action.do();
    this.record( Object.assign( {} , action , { redo: action.do } ) );
  },

  record( action ) {
    if ( this.replaying ) return;
    const now = Date.now();
    const last = this.done[ this.done.length - 1 ];
    this.undone = [];
    // Merged: the oldest undo (back to where it started) and the newest redo.
    if ( action.merge && last && last.merge === action.merge && now - last.at < this.mergeWindow ) {
      last.redo = action.redo;
      last.at = now;
      return;
    }
    this.done.push( {
      label: action.label,
      undo: action.undo,
      redo: action.redo,
      merge: action.merge,
      toast: Boolean( action.toast ),
      // screen: null opts out (the sidebar is the same on every screen).
      screen: action.screen !== undefined ? action.screen : this.hasNav() ? Nav.current() : null,
      at: now,
    } );
    if ( this.done.length > this.limit ) this.done.shift();
    // Labels are written to follow "Undone:", so one opening a sentence gets
    // a capital: "Name changed · Undo".
    if ( action.toast && action.label ) this.offer( action.label.charAt( 0 ).toUpperCase() + action.label.slice( 1 ) , "undo" );
  },

  // Nav is a top-level const, which is not a property of window, so it is
  // looked for by name.
  hasNav() {
    return typeof Nav !== "undefined";
  },

  canUndo() {
    return this.done.length > 0;
  },

  canRedo() {
    return this.undone.length > 0;
  },

  clear() {
    this.done = [];
    this.undone = [];
  },

  // A form calls this once it has saved: the field it was typed in lets go
  // of the focus, so Ctrl+Z is the app's again.
  saved( form ) {
    const active = document.activeElement;
    if ( form && active && form.contains( active ) ) active.blur();
  },

  undo() {
    return this.step( this.done , this.undone , "undo" , "undo.undone" , "redo" );
  },

  redo() {
    return this.step( this.undone , this.done , "redo" , "undo.redone" , "undo" );
  },

  // Moves the newest action from one stack to the other, running its undo or
  // redo on the way. A step that fails is dropped rather than retried
  // forever, and says so. A 409 means the server's copy has moved on since
  // (another tab, another person), so it is left alone rather than
  // overwritten.
  async step( from , to , direction , messageKey , opposite ) {
    if ( this.busy ) return;
    const action = from.pop();
    if ( !action ) {
      Dom.toast( I18n.get( "undo.nothing" ) , "ok" );
      return;
    }
    this.busy = true;
    this.replaying = true;
    try {
      if ( action.screen && this.hasNav() && Nav.current() !== action.screen ) Nav.show( action.screen );
      await action[ direction ]();
      if ( typeof Track !== "undefined" ) Track.undo( direction , action.label );
      action.merge = null;
      to.push( action );
      this.offer( this.message( messageKey , action.label ) , opposite );
    } catch ( error ) {
      const message = error && error.status === 409 ? I18n.get( "undo.conflict" )
        : error && error.message ? error.message : I18n.get( "undo.failed" );
      Dom.toast( message , "error" );
    } finally {
      this.replaying = false;
      this.busy = false;
    }
  },

  // A toast whose button goes the other way: "API key deleted · Undo",
  // "Undone: rename · Redo".
  offer( message , direction ) {
    const text = I18n.get( direction === "undo" ? "undo.button" : "undo.redo_button" );
    Dom.toast( message , "ok" , text === "" ? null : {
      text: text,
      run: () => ( direction === "undo" ? this.undo() : this.redo() ),
    } );
  },

  // "Undone: theme". An empty language.yaml key switches the toast off.
  message( key , label ) {
    const prefix = I18n.get( key );
    if ( prefix === "" ) return "";
    return label ? prefix + " " + label : prefix;
  },

  typing( target ) {
    if ( !target || !target.closest ) return false;
    return Boolean( target.closest( "input, textarea, select, [contenteditable]:not([contenteditable='false'])" ) );
  },

  onKey( event ) {
    if ( !( event.ctrlKey || event.metaKey ) || event.altKey ) return;
    if ( this.typing( event.target ) ) return;
    const key = event.key.toLowerCase();
    if ( key === "z" && !event.shiftKey ) {
      event.preventDefault();
      this.undo();
    } else if ( key === "y" || ( key === "z" && event.shiftKey ) ) {
      event.preventDefault();
      this.redo();
    }
  },
};

document.addEventListener( "keydown" , ( event ) => Undo.onKey( event ) );
