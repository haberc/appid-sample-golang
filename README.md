# How to run this application
- Install Go : https://golang.org/doc/install
- Make sure your go workspace exists in `$HOME/go`
- Unzip this app `appid.zip`, under `$HOME/go/src/`, so that the project structure is `$HOME/go/src/appid.`
- Update your AppID values in `/config/appid_config.json`. (Don't forget to add the redirect url in App ID instance, pointing to `localhost:3000/auth/callback`).
- Execute `go run main.go` from `$HOME/go/src/appid`.
- Open `localhost:3000/home`. This should show the main login page.