FROM openjdk:21-jdk-slim

LABEL authors="nhnacademy"

WORKDIR /app

COPY target/*.jar javame-gateway-api.jar

EXPOSE 10279

CMD ["java", "-jar", "javame-gateway-api.jar"]
