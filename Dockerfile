FROM tomcat:9-jdk11

# Remove default Tomcat apps
RUN rm -rf /usr/local/tomcat/webapps/*

# Change Tomcat's default port from 8080 to 3000
RUN sed -i 's/port="8080"/port="3000"/' /usr/local/tomcat/conf/server.xml

# Copy the locally-built WAR into Tomcat
COPY build/libs/mvc-auth-commons-*.war /usr/local/tomcat/webapps/ROOT.war

EXPOSE 3000 5005

ENV JAVA_OPTS="-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005"

CMD ["catalina.sh", "run"]
