# iPB (iOS Push Bridge)

A self-hosted Pushover alternative for family and friends. People add iPB to their iPhone Home Screen once, and your scripts can then send them push notifications with a single HTTP request.

There is no native app and no App Store involved. iPB is a Go web server and a Home Screen web app, using the Web Push support that iOS has had since 16.4.

## How it works

- **One install:** iPB is the only thing people add to their Home Screen.
- **Virtual apps:** apps such as "Doorbell" or "Backups" live inside iPB. Each has its own name, icon, sound and token.
- **Sending:** a send needs an app token and a user or group key. Holding both is the whole permission.
- **Inbox:** every message is kept in iPB's inbox for 30 days, and you can filter it by app.
- **Muting:** each person can mute any app. Muted messages still reach the inbox, but no push is sent.
- **Groups:** the creator picks the members, and any member can leave.

## Running it

iPhones need public HTTPS for both install and push, so localhost is only good for working on the UI.

Run it from a checkout, for development or a private box:

```bash
scripts/run.sh
```

Print a sign-in link for the owner:

```bash
scripts/login.sh
```

Run it in Docker, which is the better choice for anything long-lived or internet-facing:

```bash
docker/run.sh
```

Build self-contained binaries with the frontend compiled in:

```bash
scripts/build.sh
```

Everything is configured in `config/config.yaml`, and nothing reads environment variables. The first run writes that file along with `config/secret.key`. Before testing on a phone, set `server.public_url` to your HTTPS address. Back up `secret.key` and the app directory together, because the data can't be read without the key.

Other admin commands go through `scripts/run.sh manage`, for example:

```bash
scripts/run.sh manage list-users
```

## Installing on an iPhone

1. Open your iPB address in Safari, using a sign-in or invite link from the owner.
2. Follow the "Add iPB to your Home Screen" card.
3. Open iPB from the new icon. Push only works from there, not from a Safari tab.
4. Turn on notifications and send yourself a test.

## Sending a message

```bash
curl https://your-host/api/v1/messages -d token=APP_TOKEN -d user=USER_OR_GROUP_KEY -d message="Someone is at the door"
```

The API takes JSON or a form and uses Pushover's field names, and it's also available at `/1/messages.json`. Fields it doesn't know are ignored, so existing Pushover scripts should work once they point at your server. The token can go in `Authorization: Bearer` instead.

| Field | Required | Notes |
|---|---|---|
| `token` | Yes | App token, shown once when the app is created or rotated |
| `user` | Yes | User or group key |
| `message` | Yes | Up to 1024 characters |
| `title` | No | Up to 250 characters |
| `url`, `url_title` | No | An http(s) link shown in the inbox |
| `priority` | No | -2 to 2, see below |
| `ttl` | No | Seconds, up to 28 days |
| `retry`, `expire` | No | For priority 2: seconds between re-sends (30 minimum, default 60) and how long to keep going (3 hours maximum, default 1 hour) |

| Priority | What happens |
|---|---|
| -2 | Inbox only, no push |
| -1 | Sent as silent |
| 0 | Normal |
| 1 | Sent with `Urgency: high` |
| 2 | Re-sent until acknowledged |

The full API is described in `config/openapi.json`, and a running server serves it at `/api/openapi.json`.

## iOS limits

Being one Home Screen web app has a few costs:

- **Icon:** every notification shows the iPB icon. App icons only appear inside iPB, so the notification title carries the app's name, as `<App>` or `<App>: <title>`.
- **Sound:** every push plays the system notification sound. See below.

## Custom sounds

**A push to an iOS web app can't play a custom sound.** Web Push has no sound field, you don't control the APNs payload (Apple's push service builds it), and a service worker can't play audio.

What iPB does instead:

- Each app can have its own sound (MP3, M4A, WAV, AIFF or CAF, up to 900 KB).
- That sound only plays while iPB is open, and only after a tap in that launch, because iOS blocks audio until then. A message that arrives before the first tap is silent.
- When iPB is closed or the phone is locked, you get the system sound.

What the person can change on their iPhone:

- Sound on or off for iPB, in Settings > Notifications.
- The default alert tone, in Settings > Sounds & Haptics. This applies to every app that uses the default, not just iPB.

## Option: a native wrapper

Real custom push sounds need a native app, which can set `aps.sound` in the payload. That is how Pushover does it. A thin wrapper around iPB would be enough, and only one is needed, since the virtual apps all live inside it. Sounds wouldn't have to ship in the build, because a native app can download them into its `Library/Sounds` folder.

The server would also have to send through APNs directly for those devices, as well as through Web Push.

All of the ways to distribute it need the Apple Developer Program, at $99/year. That fee is a membership rather than hosting: it covers signing apps and using APNs, and Apple hosts TestFlight and App Store builds at no extra charge. A free Apple account can't use push, and apps installed with one expire after 7 days.

| Option | What people do | Catch |
|---|---|---|
| **TestFlight** | Install TestFlight from the App Store, tap your invite link, then install the app | Each build expires after 90 days, and the first build for outside testers gets a light review. Up to 10,000 testers |
| **App Store** | One normal install | Full review, and thin website wrappers can be rejected under guideline 4.2 |
| **Self-hosted IPA (ad hoc)** | Install from your own link | Each device must be registered first, up to 100 per device type per year |

TestFlight is Apple's official beta-testing app. It's the quickest way to prove the sounds work, but it isn't a good permanent home, because a new build has to be uploaded at least every 90 days or the app stops opening. The same build can go to the App Store later.

None of this is built. These notes were written from memory in November 2026, so check Apple's current limits and pricing before paying for anything.

## Project layout

| Path | What's there |
|---|---|
| `main.go` | Entry point |
| `server/routes/` | HTTP handlers, including the send API in `send.go` |
| `server/push/` | Push delivery queue and retries |
| `server/encryption/webpush.go` | Web Push encryption |
| `server/models/` | Stored records |
| `static/` | Frontend and service worker (`sw.js`) |
| `config/` | Settings, UI text (`language.yaml`) and the API definition |
| `scripts/`, `docker/` | Run, sign-in, build and Docker scripts |

Run the tests with:

```bash
go test ./...
```
