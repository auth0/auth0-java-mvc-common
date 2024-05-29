pluginManagement {
    repositories {
        gradlePluginPortal()
    }
    plugins {
        id("com.auth0.gradle.oss-library.java") version "0.18.0"
    }
}

rootProject.name = "opengov-auth0-mvc-auth-commons"

include("main")