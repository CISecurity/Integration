package org.cisecurity.ietf.sacm.tst

import org.jivesoftware.smack.AbstractXMPPConnection
import org.jivesoftware.smack.ConnectionConfiguration
import org.jivesoftware.smack.SmackException
import org.jivesoftware.smack.XMPPException
import org.jivesoftware.smack.tcp.XMPPTCPConnection
import org.jivesoftware.smack.tcp.XMPPTCPConnectionConfiguration
import org.jivesoftware.smackx.pubsub.LeafNode
import org.jivesoftware.smackx.pubsub.PayloadItem
import org.jivesoftware.smackx.pubsub.PubSubManager
import org.jivesoftware.smackx.pubsub.SimplePayload
import org.slf4j.LoggerFactory

/**
 * Created by wmunyan on 3/3/2018.
 */
class AddToAssessmentResults {
	def ci  = "scap_org.cisecurity_collection_1.2.0_CIS_Microsoft_Windows_10_Enterprise_Release_1607_Benchmark"
	def xml = "<arf_get_url xmlns=\"pubsub:arf:url\">https://ip-0a1e0af4:7443/httpfileupload/4eb87103-4700-4e3a-9240-c3f46275bbb6/CIS-CAT-DEV-CIS_Microsoft_Windows_10_Enterprise_Release_1607_Benchmark-ARF-20180305T095053Z.xml</arf_get_url>"

	def log = LoggerFactory.getLogger(AddToAssessmentResults.class)

	Properties properties = new Properties()
	XMPPTCPConnectionConfiguration config
	AbstractXMPPConnection connection
	PubSubManager pubsubManager

	final String NODE_NAME = "AssessmentResults"
	LeafNode results

	static void main(String[] args) {
		new AddToAssessmentResults().execute()
	}

	def execute() {
		initializeXmpp()

		def sp = new SimplePayload(
			"arf_get_url",
			"pubsub:arf:url",
			xml
		)
		def pi = new PayloadItem(ci, sp)

		// Publish an Item with payload
		try {
			results.publish(pi)

			log.info "Published"
		} catch (SmackException.NoResponseException nre) {
			log.error "No Response Exception: Probably a timeout", nre
		}
		disconnectXmpp()
	}

	def initializeXmpp() {
		log.info "Loading XMPP connection properties..."
		properties.load(getClass().getResourceAsStream("/conn.properties"))

		log.info "Configuring XMPP connection..."
		config = XMPPTCPConnectionConfiguration.builder()
			.setUsernameAndPassword(properties.user, properties.password)
			.setXmppDomain(properties.xmppdomain)
			.setHost(properties.host)
			.setPort(Integer.parseInt(properties.port))
			.setSecurityMode(ConnectionConfiguration.SecurityMode.disabled)
			.build()

		log.info "Connecting to XMPP server as user ${properties.user}..."
		connection = new XMPPTCPConnection(config)
		connection.setReplyTimeout(600000) // Reply timeout == 600 sec.
		connection.connect().login()

		log.info "Getting the PubSubManager..."

		// Create a pubsub manager using an existing XMPPConnection
		pubsubManager = PubSubManager.getInstance(connection)

		try {
			results = pubsubManager.getLeafNode(NODE_NAME)

			log.info "Found topic --> ${NODE_NAME}"

			def jid = connection.user.asEntityBareJidString()
			def subs = results.subscriptions
			def found = subs.find { s -> s.jid == jid }
			if (!found) {
				log.info "Subscribing JID --> ${jid} to topic --> ${NODE_NAME}"
				results.subscribe(jid)
			} else {
				log.info "JID --> ${jid} is already subscribed to topic --> ${NODE_NAME}"
			}
		} catch (XMPPException.XMPPErrorException e) {
			log.error "Exception when retrieving topic --> ${NODE_NAME}", e
		}
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
