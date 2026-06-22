extension {
    name = "extensions/all/misc/screenshot/remove-screenshot-restriction.mpe"
}

android {
    namespace = "app.morphe.extension.all.misc.screenshot.removerestriction"

    defaultConfig {
        minSdk = 21
    }
}

dependencies {
    compileOnly(libs.annotation)
    compileOnly(libs.morphe.extensions.library)
}
