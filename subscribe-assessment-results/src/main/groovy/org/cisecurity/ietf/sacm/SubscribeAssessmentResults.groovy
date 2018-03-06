package org.cisecurity.ietf.sacm

import groovy.swing.SwingBuilder
import org.jivesoftware.smack.AbstractXMPPConnection
import org.jivesoftware.smack.ConnectionConfiguration
import org.jivesoftware.smack.tcp.XMPPTCPConnection
import org.jivesoftware.smack.tcp.XMPPTCPConnectionConfiguration
import org.jivesoftware.smackx.pubsub.PubSubManager
import org.slf4j.LoggerFactory

import javax.swing.JFrame
import java.awt.BorderLayout

/**
 * Subscribe to the "assessment-results" topic
 * Grab ARF
 * Push to CCPD
 * Created by wmunyan on 2/16/2018.
 */
class SubscribeAssessmentResults {
	def log = LoggerFactory.getLogger(SubscribeAssessmentResults.class)

	Properties properties = new Properties()
	XMPPTCPConnectionConfiguration config
	AbstractXMPPConnection connection
	PubSubManager pubsubManager

	/**
	 * Startup
	 * @param args
	 */
	static void main(String[] args) {
		new SubscribeAssessmentResults().execute()
	}

	/**
	 * Listen
	 */
	void execute() {
		log.info "Connecting to XMPP Server..."
		initializeXmpp()

		log.info "Subscribing to assessment results topic..."
		ResultsSubscription cs =
			new ResultsSubscription(
				jid: connection.user.asEntityBareJidString(),
				url: properties.ccpdurl,
				token: properties.ccpdtoken)
		cs.subscribe(pubsubManager)

		log.info "Listening..."
		log.info "-------------------------------------------------"
		log.info ""

		def swing = new SwingBuilder()
		swing.edt {
			frame(id: "results_listener", title: "Listener", size: [300, 300], show: true, defaultCloseOperation: JFrame.EXIT_ON_CLOSE,
				windowClosing: { disconnectXmpp() }) {

				borderLayout()

				textlabel1 = label(text: "Listening for new Results", constraints: BorderLayout.NORTH)
			}
		}
	}

	def initializeXmpp() {
		log.info "Loading XMPP connection properties..."
		properties.load(getClass().getResourceAsStream("/conn.properties"))

		log.info "Configuring XMPP connection..."
		config = XMPPTCPConnectionConfiguration.builder()
			.setUsernameAndPassword(properties.resultsconsumeruser, properties.resultsconsumerpwd)
			.setXmppDomain(properties.xmppdomain)
			.setHost(properties.host)
			.setPort(Integer.parseInt(properties.port))
			.setSecurityMode(ConnectionConfiguration.SecurityMode.disabled)
			.build()

		log.info "Connecting to XMPP server as user ${properties.resultsconsumeruser}..."
		connection = new XMPPTCPConnection(config)
		connection.setReplyTimeout(60000) // Reply timeout == 60 sec.
		connection.connect().login()

		log.info "Getting the PubSubManager..."

		// Create a pubsub manager using an existing XMPPConnection
		pubsubManager = PubSubManager.getInstance(connection)

		log.info "Connected."
	}

	/**
	 * Disconnect from the XMPP server
	 * @return
	 */
	def disconnectXmpp() {
		log.info "Disconnecting from XMPP Server..."
		connection.disconnect()
		log.info "Disconnected"
	}
}
