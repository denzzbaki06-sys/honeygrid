FROM maven:3.9.16-eclipse-temurin-21 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn --batch-mode verify

FROM eclipse-temurin:21-jre
WORKDIR /app
RUN groupadd --system honeygrid && useradd --system --gid honeygrid honeygrid && mkdir /app/data && chown honeygrid:honeygrid /app/data
COPY --from=build /app/target/honeygrid-0.0.1-SNAPSHOT.jar app.jar
USER honeygrid
EXPOSE 8082 2222
ENTRYPOINT ["java", "-jar", "app.jar"]
