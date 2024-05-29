plugins {
    id("java-common-conventions")
    id("maven-publish")
    id("pl.allegro.tech.build.axion-release")
}

dependencies {
    implementation("jakarta.servlet:jakarta.servlet-api:6.0.0")
    implementation("org.apache.commons:commons-lang3:3.12.0")
    implementation("com.google.guava:guava-annotations:r03")
    implementation("commons-codec:commons-codec:1.15")

    api("com.auth0:auth0:2.11.0")
    api("com.auth0:java-jwt:3.19.4")
    api("com.auth0:jwks-rsa:0.22.1")

    testImplementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
    testImplementation("org.hamcrest:hamcrest:2.2")
    testImplementation("org.mockito:mockito-core:5.12.0")
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    testImplementation("org.springframework:spring-test:6.1.8")
    testImplementation("com.squareup.okhttp3:okhttp:4.12.0")
}

version = "1.0.0"

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            groupId = "com.opengov"
            artifactId = "opengov-auth0-mvc-auth-commons"
            from(components["java"])
        }
    }
    repositories {
        maven {
            val releasesRepoUrl = uri("https://artifactory.opengov.zone:443/artifactory/maven-release-local/")
            val snapshotsRepoUrl = uri("https://artifactory.opengov.zone:443/artifactory/maven-snapshot-local/")
            url = if (version.toString().endsWith("SNAPSHOT")) snapshotsRepoUrl else releasesRepoUrl
            credentials {
                username = System.getenv("INTERNAL_MAVEN_PUBLISH_USER")
                password = System.getenv("INTERNAL_MAVEN_PUBLISH_PASS")
            }
        }
    }
}

tasks.jacocoTestReport {
    finalizedBy("jacocoTestCoverageVerification")
}

tasks.jacocoTestCoverageVerification {
    violationRules {
        rule {
            limit {
                counter = "INSTRUCTION"
                minimum = "0.15".toBigDecimal()
            }
        }
    }
}
