// Custom sounds. Web Push has no way to choose a sound, so an app's sound plays
// only while iPB is open. iOS allows audio only after a tap in each launch, so
// the first tap anywhere unlocks it; a message arriving before that is silent.
//
// Through fetch and decodeAudioData rather than <audio>: the server answers
// these without byte ranges, which Safari's media element insists on.
const Sounds = {
  context: null,
  decoded: {},

  init() {
    const unlock = () => {
      this.ready();
      document.removeEventListener( "pointerdown" , unlock );
    };
    document.addEventListener( "pointerdown" , unlock );
  },

  ready() {
    if ( !this.context ) {
      const Context = window.AudioContext || window.webkitAudioContext;
      if ( !Context ) return null;
      this.context = new Context();
    }
    if ( this.context.state === "suspended" ) this.context.resume();
    return this.context;
  },

  async play( appId , version ) {
    const context = this.context;
    if ( !context || context.state !== "running" ) return;
    const name = appId + "/" + version;
    if ( !this.decoded[ name ] ) {
      const response = await fetch( "/api/apps/" + appId + "/sound?v=" + version , { credentials: "same-origin" } );
      if ( !response.ok ) return;
      this.decoded[ name ] = await context.decodeAudioData( await response.arrayBuffer() );
    }
    const source = context.createBufferSource();
    source.buffer = this.decoded[ name ];
    source.connect( context.destination );
    source.start();
  },

  // A tap on Play: that tap is what lets it sound.
  async preview( appId , version ) {
    this.ready();
    try {
      await this.play( appId , version );
    } catch ( error ) {
      App.showError( I18n.get( "apps.sound_failed" ) );
    }
  },
};
