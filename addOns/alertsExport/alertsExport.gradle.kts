version = "1"
description = "Allows you to export Alerts after scan is completed."

zapAddOn {
    addOnName.set("Alert Export")
    zapVersion.set("2.8.0")

    manifest {
        author.set("Cloudanix")
    }
}

dependencies {
    implementation("org.apache.httpcomponents:httpmime:4.5.2")
}
