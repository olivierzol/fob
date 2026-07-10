# Homebrew cask for fob.
#
# Casks are served from a *tap* repo whose name starts with "homebrew-", so this
# file's real home is the olivierzol/homebrew-fob repo (path: Casks/fob.rb). Users
# then install with:
#
#   brew install --cask olivierzol/fob/fob
#
# On each release, bump `version` and `sha256` (the .zip's SHA-256, printed by
# Scripts/release.sh). Homebrew downloads the already notarized + stapled .app, so
# Gatekeeper and notifications (with the fob icon) work on every user's machine.
cask "fob" do
  version "0.3.0"
  sha256 "4e22f32d4069f02482961a7b94319caf5141d8f9e2f7c09c069997090f1a2902"

  url "https://github.com/olivierzol/fob/releases/download/v#{version}/fob-#{version}.zip",
      verified: "github.com/olivierzol/fob/"
  name "fob"
  desc "Secure Enclave SSH keys gated by Touch ID"
  homepage "https://github.com/olivierzol/fob"

  depends_on macos: :ventura # minimum macOS 13 (matches LSMinimumSystemVersion)

  app "fob.app"
  # Expose the bundled CLI on PATH as `fob`.
  binary "#{appdir}/fob.app/Contents/MacOS/fob-cli", target: "fob"

  # `brew uninstall --zap` removes user state too.
  zap trash: [
    "~/.fob",
    "~/Library/Preferences/dev.fob.app.plist",
    "~/Library/LaunchAgents/dev.fob.agent.plist", # legacy CLI-era launchd agent
  ]
end
