// QR codes: for the authenticator app, and for getting a login or invite link
// onto a phone without typing it.
const Qr = {
  // Black on white whatever the theme: scanners want the contrast, and four
  // modules of margin.
  draw( canvas , text ) {
    const code = qrcode( 0 , "M" );
    code.addData( text );
    code.make();
    const quiet = 4;
    const scale = 5;
    const count = code.getModuleCount();
    canvas.width = canvas.height = ( count + quiet * 2 ) * scale;
    const context = canvas.getContext( "2d" );
    context.fillStyle = "#ffffff";
    context.fillRect( 0 , 0 , canvas.width , canvas.height );
    context.fillStyle = "#000000";
    for ( let row = 0; row < count; row++ ) {
      for ( let column = 0; column < count; column++ ) {
        if ( code.isDark( row , column ) ) {
          context.fillRect( ( column + quiet ) * scale , ( row + quiet ) * scale , scale , scale );
        }
      }
    }
  },

  // A button that shows and hides the code for the link in value. A link is
  // spent once used, so whoever shows a new one calls hide, or the code on
  // screen would still be the old link's.
  toggle( button , canvas , value ) {
    button.addEventListener( "click" , () => {
      if ( canvas.hidden ) this.draw( canvas , value.textContent );
      Dom.show( canvas , canvas.hidden );
    } );
  },

  hide( canvas ) {
    Dom.show( canvas , false );
  },
};
