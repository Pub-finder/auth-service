plugins {
	java
	id("org.springframework.boot") version "3.3.4"
	id("io.spring.dependency-management") version "1.1.6"
}

group = "com.pubfinder"
version = "0.0.1-SNAPSHOT"

java {
	sourceCompatibility = JavaVersion.VERSION_17
}

repositories {
	mavenCentral()
}

dependencies {
	implementation("org.springframework.boot:spring-boot-starter-cache")
	implementation("org.springframework.boot:spring-boot-starter-data-jpa")
	implementation("org.springframework.boot:spring-boot-starter-web")
	developmentOnly("org.springframework.boot:spring-boot-devtools")
	runtimeOnly("org.postgresql:postgresql")
	testImplementation("org.springframework.boot:spring-boot-starter-test")
	compileOnly("org.projectlombok:lombok")
	annotationProcessor("org.projectlombok:lombok")
	implementation("org.mapstruct:mapstruct:1.5.5.Final")
	testImplementation("com.h2database:h2:2.2.224")

	implementation("org.springframework.boot:spring-boot-starter-security")
	testImplementation("org.springframework.security:spring-security-test")

	implementation("com.giffing.bucket4j.spring.boot.starter:bucket4j-spring-boot-starter:0.11.0")
	implementation("org.springframework.boot:spring-boot-starter-validation:3.2.3")
	implementation("org.springframework.boot:spring-boot-starter-cache")
	implementation("javax.cache:cache-api")

	implementation("com.github.ben-manes.caffeine:caffeine:3.1.8")
	implementation("com.github.ben-manes.caffeine:jcache")

	implementation("io.jsonwebtoken:jjwt-api:0.12.5")
	runtimeOnly("io.jsonwebtoken:jjwt-impl:0.12.5")
	runtimeOnly("io.jsonwebtoken:jjwt-jackson:0.12.5")

	implementation("io.hypersistence:hypersistence-utils-hibernate-63:3.7.3")
	implementation("org.postgresql:postgresql:42.7.3")

	testImplementation("org.testcontainers:postgresql:1.19.7")
	implementation("com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.17.0")

	implementation("com.google.guava:guava:17.0")
	implementation("org.json:json:20240303")
}

tasks.withType<Test> {
	useJUnitPlatform()
}
