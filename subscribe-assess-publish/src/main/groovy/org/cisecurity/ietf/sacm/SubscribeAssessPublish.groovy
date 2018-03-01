package org.cisecurity.ietf.sacm

import groovy.swing.SwingBuilder
import org.cisecurity.assessor.util.AssessorUtilities
import org.jivesoftware.smack.AbstractXMPPConnection
import org.jivesoftware.smack.ConnectionConfiguration
import org.jivesoftware.smack.tcp.XMPPTCPConnection
import org.jivesoftware.smack.tcp.XMPPTCPConnectionConfiguration
import org.jivesoftware.smackx.httpfileupload.HttpFileUploadManager
import org.jivesoftware.smackx.pubsub.PubSubManager
import org.slf4j.LoggerFactory

import javax.swing.JFileChooser
import javax.swing.JFrame
import java.awt.BorderLayout

/**
 * Subscribe to the "assessment-content" topic
 * Receive new content
 * Perform assessment
 * Generate results
 * Publish to "assessment-results" topic
 *
 * Created by wmunyan on 2/16/2018.
 */
class SubscribeAssessPublish {
	def log = LoggerFactory.getLogger(SubscribeAssessPublish.class)

	XMPPTCPConnectionConfiguration config
	AbstractXMPPConnection         connection
	PubSubManager                  pubsubManager
	HttpFileUploadManager          fileUploadManager

	/**
	 * Startup
	 * @param args
	 */
	static void main(String[] args) {
		new SubscribeAssessPublish().execute()
	}

	/**
	 * Listen
	 */
	void execute() {

		log.info "Connecting to XMPP Server..."
		initializeXmpp()

		log.info "Joining results topic for publishing..."
		ResultsPublisher rp = new ResultsPublisher(hfum: fileUploadManager)
		rp.subscribe(pubsubManager)

		log.info "Subscribing to content topic..."
		ContentSubscription cs =
			new ContentSubscription(
				jid: connection.user.asEntityBareJidString(),
				pub: rp)
		cs.subscribe(pubsubManager)

		log.info "Listening..."
		log.info "-------------------------------------------------"
		log.info ""

		def swing = new SwingBuilder()
		swing.edt {
			frame(id: "listener", title: "Listener", size: [300, 300], show: true, defaultCloseOperation: JFrame.EXIT_ON_CLOSE,
				windowClosing: { disconnectXmpp() }) {

				borderLayout()

				textlabel1 = label(text: "Listening", constraints: BorderLayout.NORTH)
			}
		}
	}

	def initializeXmpp() {
		log.info "Loading Assessor properties..."
		AssessorUtilities.instance.userProperties = new Properties()
		AssessorUtilities.instance.userProperties.load(getClass().getResourceAsStream("/assessor.properties"))

		log.info "Loading XMPP connection properties..."
		Properties properties = new Properties()
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
		pubsubManager     = PubSubManager.getInstance(connection)
		fileUploadManager = HttpFileUploadManager.getInstanceFor(connection)

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

//		swing.edt {
//			fc1 = fileChooser(currentDirectory: new File(System.properties["user.dir"]), fileSelectionMode: JFileChooser.FILES_ONLY)
//			frame(title: 'Frame', size: [300, 300], show: true, defaultCloseOperation: JFrame.EXIT_ON_CLOSE, id: "frame") {
//				borderLayout()
//				textlabel = label(text: 'Select content to publish', constraints: BorderLayout.NORTH)
//				button(text: 'Browse',
//					actionPerformed: {
//						def rv = fc1.showOpenDialog(swing.frame)
//						if (rv == JFileChooser.APPROVE_OPTION) {
//							File f = fc1.selectedFile
//							println f.absolutePath
//
//							def tw = new TopicWrapper(topicName: "PayloadNode")
//							tw.initialize()
//							tw.retrieveOrCreateTopic()
//							tw.publishCollection(f.absolutePath)
//						}
//					}, constraints: BorderLayout.SOUTH)
//			}
//		}
//	}
}
