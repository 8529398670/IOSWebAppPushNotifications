// iPB's service worker.
//
// iOS 18.4 and later show a push by themselves from its JSON, so on those
// phones this only matters for what happens on a tap. Older iOS and other
// browsers need it to show anything at all. iOS revokes the permission of a web
// app that receives a push and shows nothing, so a push handler here must
// always end in a notification.
self.addEventListener( "install" , () => self.skipWaiting() );
self.addEventListener( "activate" , ( event ) => event.waitUntil( self.clients.claim() ) );

self.addEventListener( "push" , ( event ) => {
  // A declarative push already carries a notification the browser will show.
  if ( event.notification ) return;

  let message = {};
  try {
    message = event.data ? event.data.json() : {};
  } catch ( error ) {
    message = {};
  }
  const notification = message.notification || {};
  const shown = self.registration.showNotification( notification.title || "iPB" , {
    body: notification.body || "",
    silent: notification.silent === true,
    data: { navigate: notification.navigate || "/#inbox" },
  } );
  const badge = notification.app_badge && self.navigator.setAppBadge
    ? self.navigator.setAppBadge( Number( notification.app_badge ) )
    : Promise.resolve();
  event.waitUntil( Promise.all( [ shown , badge ] ) );
} );

self.addEventListener( "notificationclick" , ( event ) => {
  event.notification.close();
  const target = ( event.notification.data && event.notification.data.navigate ) || "/#inbox";
  event.waitUntil( ( async () => {
    const open = await self.clients.matchAll( { type: "window" , includeUncontrolled: true } );
    for ( const client of open ) {
      if ( "focus" in client ) {
        await client.navigate( target );
        return client.focus();
      }
    }
    return self.clients.openWindow( target );
  } )() );
} );
