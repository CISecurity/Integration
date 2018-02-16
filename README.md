# Integration: PoC to enable XMPP integrations between SACM Components
An architecture proposal has been made to the SACM working group, and this repository holds proof of concept code for the scenario described below. The proposed architecture looks something like this:

![Proposed Architecture](https://raw.githubusercontent.com/CISecurity/Integration/master/docs/img/mandm-arch.png)

#Scenario 1: New Configuration Assessment Available

![Configuration Assessment Scenario](https://raw.githubusercontent.com/CISecurity/Integration/master/docs/img/ietf-101-hackathon%202.png)

1. New configuration assessment content is published (via mockup policy source)
2. Configuration assessment publisher interface puts new content "on the grid"
3. Configuration assessment subscriber receives new content and passes to the assessment engine
4. Assessment engine interprets new content
5. Assessment engine collects data
6. Assessment engine evaluates data
7. Configuration assessment results are put "on the grid"
8. Configuration assessment results subscriber receives new results
9. Results subscriber imports results

We hope to largely configure (using [Openfire](https://www.igniterealtime.org/projects/openfire/)}) an XMPP-Grid with little or no additional coding (per the latest [XMPP-Grid specification](https://datatracker.ietf.org/doc/draft-ietf-mile-xmpp-grid/)). Additionally, we intend to use an existing assessment engine and results aggregator ([CIS-CAT Pro](https://www.cisecurity.org/cybersecurity-tools/cis-cat-pro/) from CIS). This means we'll be primarily responsible for coding the following components:

1. A mocked content publication engine
2. Configuration assessment content publishing component
3. Configuration assessment content subscriber component
4. Configuration assessment results publishing component
5. Configuration assessment results subscriber component
