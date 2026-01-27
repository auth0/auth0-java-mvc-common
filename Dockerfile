FROM gradle:6.9.2-jdk8

WORKDIR /home/gradle
# Copy your project files
COPY . .

# Ensure the Gradle wrapper is executable
RUN chmod +x ./gradlew

# Expose both ports for your MCD test
EXPOSE 3000
EXPOSE 8080
EXPOSE 5005

# Use --no-daemon to keep the container process alive
# We use the wrapper (./gradlew) to ensure consistency
#CMD ["./gradlew", "appRun", "--no-daemon", "-Pgretty.managed=false"]
ENV GRADLE_OPTS="-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005"
CMD ["gradle", "appRun", "--no-daemon"]