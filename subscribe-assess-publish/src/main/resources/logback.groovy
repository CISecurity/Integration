import ch.qos.logback.classic.encoder.PatternLayoutEncoder
import ch.qos.logback.core.ConsoleAppender
import ch.qos.logback.core.rolling.FixedWindowRollingPolicy
import ch.qos.logback.core.rolling.RollingFileAppender
import ch.qos.logback.core.rolling.SizeBasedTriggeringPolicy

import static ch.qos.logback.classic.Level.INFO

/**
 * Created by wmunyan on 2/23/2018.
 */
// See http://logback.qos.ch/manual/groovy.html for details on configuration
//appender('STDOUT', ConsoleAppender) {
//    encoder(PatternLayoutEncoder) {
//        pattern = "%level %logger - %msg%n"
//    }
//}

def logDirectory = "."
//if (System.getenv("ASSESSOR_CLI_LOGDIR")) {
//    logDirectory = System.getenv("ASSESSOR_CLI_LOGDIR")
//}

appender("ROLLING", RollingFileAppender) {
	encoder(PatternLayoutEncoder) {
		Pattern = "%d{dd/MM/yyyy HH:mm:ss.SSS} %level %logger - %msg%n"
	}
	file = "${logDirectory}/logs/subscribe-assess-publish.log"
	rollingPolicy(FixedWindowRollingPolicy) {
		fileNamePattern = "${logDirectory}/logs/subscribe-assess-publish.%i.log"
		minIndex = 1
		maxIndex = 21
	}
	triggeringPolicy(SizeBasedTriggeringPolicy) {
		maxFileSize = "35MB"
	}
}

//root(INFO, ["STDOUT"])
root(INFO, ["ROLLING"])
