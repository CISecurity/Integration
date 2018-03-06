import ch.qos.logback.classic.encoder.PatternLayoutEncoder
import ch.qos.logback.core.ConsoleAppender

//import ch.qos.logback.core.ConsoleAppender
import ch.qos.logback.core.rolling.FixedWindowRollingPolicy
import ch.qos.logback.core.rolling.RollingFileAppender
import ch.qos.logback.core.rolling.SizeBasedTriggeringPolicy

// See http://logback.qos.ch/manual/groovy.html for details on configuration
appender('STDOUT', ConsoleAppender) {
    encoder(PatternLayoutEncoder) {
        pattern = "%level %logger - %msg%n"
    }
}

def logDirectory = "."
//if (System.getenv("CCPD_LOG_DIR")) {
//    logDirectory = System.getenv("CCPD_LOG_DIR")
//}

appender("ROLLING", RollingFileAppender) {
    encoder(PatternLayoutEncoder) {
        Pattern = "%d{MM/dd/yyyy HH:mm:ss.SSS} %level %logger - %msg%n"
    }
    file = "${logDirectory}/ccpalogs/ccpa.log"
    rollingPolicy(FixedWindowRollingPolicy) {
        fileNamePattern = "${logDirectory}/ccpalogs/ccpa.%i.log"
        minIndex = 1
        maxIndex = 21
    }
    triggeringPolicy(SizeBasedTriggeringPolicy) {
        maxFileSize = "25MB"
    }
}

root(INFO, ["STDOUT"])
//root(INFO, ["ROLLING"])
