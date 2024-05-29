import net.ltgt.gradle.errorprone.errorprone

plugins {
    java
    jacoco
    id("com.diffplug.spotless")
    id("net.ltgt.errorprone")
    id("org.sonarqube")
}

repositories {
    mavenCentral() //TODO: Remove this once we have all packages cached by Artifactory
    maven {
        url = uri("https://artifactory.opengov.zone:443/artifactory/maven-all/")
        credentials {
            username = System.getenv("INTERNAL_MAVEN_USER")
            password = System.getenv("INTERNAL_MAVEN_PASS")
        }
    }
}

jacoco {
    toolVersion = "0.8.8"
}


java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

dependencies {
    errorprone("com.google.errorprone:error_prone_core:2.26.1")
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
}


spotless {
    java {
        googleJavaFormat("1.15.0")
    }
}

tasks.withType<JavaCompile> {
    options.compilerArgs.addAll(listOf("-Xlint:unchecked", "-Xlint:deprecation", "-Werror"))
    options.errorprone.isEnabled.set(true)
    options.errorprone.disable("SameNameButDifferent", "MissingSummary", "JavaTimeDefaultTimeZone", "ObjectEqualsForPrimitives", "AlmostJavadoc","UnusedVariable")
}

tasks.named("check") {
    dependsOn("spotlessCheck")
}

tasks.withType<Test> {
    useJUnitPlatform()
    finalizedBy("jacocoTestReport")
}

tasks.jacocoTestReport {
    reports {
        xml.required.set(true)
        csv.required.set(true)
        html.outputLocation.set(layout.buildDirectory.dir("jacocoHtml"))
    }
}
