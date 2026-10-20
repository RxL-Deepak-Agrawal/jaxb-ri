/*
 * Copyright (c) 2026 RxLogix Corporation. All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Distribution License v. 1.0, which is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

package org.glassfish.jaxb.core.v2.util;

import java.io.File;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.SAXParser;

import junit.framework.TestCase;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

/**
 * CVE-2026-92877: parsers created by {@link XmlFactory} with security on must reject
 * DOCTYPE declarations and never resolve external entities, whichever JAXP implementation
 * is on the classpath (JDK built-in or Apache Xerces).
 */
public class XmlFactoryXxeTest extends TestCase {

    private static final String SAX_FACTORY = "javax.xml.parsers.SAXParserFactory";
    private static final String DOM_FACTORY = "javax.xml.parsers.DocumentBuilderFactory";
    private static final String XERCES_SAX = "org.apache.xerces.jaxp.SAXParserFactoryImpl";
    private static final String XERCES_DOM = "org.apache.xerces.jaxp.DocumentBuilderFactoryImpl";

    private static final String SECRET = "rx-secret-value";

    private File secretFile;

    @Override
    protected void setUp() throws Exception {
        secretFile = File.createTempFile("xxe-secret", ".txt");
        secretFile.deleteOnExit();
        Files.write(secretFile.toPath(), SECRET.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    protected void tearDown() {
        System.clearProperty(SAX_FACTORY);
        System.clearProperty(DOM_FACTORY);
        secretFile.delete();
    }

    private String payload() {
        return "<?xml version=\"1.0\"?>"
                + "<!DOCTYPE root [<!ENTITY xxe SYSTEM \"" + secretFile.toURI() + "\">]>"
                + "<root>&xxe;</root>";
    }

    public void testSaxRejectsExternalEntityWithJdkParser() throws Exception {
        assertSaxRejected();
    }

    public void testSaxRejectsExternalEntityWithXerces() throws Exception {
        System.setProperty(SAX_FACTORY, XERCES_SAX);
        assertSaxRejected();
    }

    public void testDomRejectsExternalEntityWithJdkParser() throws Exception {
        assertDomRejected();
    }

    public void testDomRejectsExternalEntityWithXerces() throws Exception {
        System.setProperty(DOM_FACTORY, XERCES_DOM);
        assertDomRejected();
    }

    /** Guards the tests above: with security explicitly disabled, the same document parses. */
    public void testXercesResolvesEntityWhenSecurityDisabled() throws Exception {
        System.setProperty(DOM_FACTORY, XERCES_DOM);
        DocumentBuilder builder = XmlFactory.createDocumentBuilderFactory(true).newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(payload())));
        assertEquals(SECRET, doc.getDocumentElement().getTextContent());
    }

    private void assertSaxRejected() throws Exception {
        SAXParser parser = XmlFactory.createParserFactory(false).newSAXParser();
        StringBuilder text = new StringBuilder();
        try {
            parser.parse(new InputSource(new StringReader(payload())), new DefaultHandler() {
                @Override
                public void characters(char[] ch, int start, int length) {
                    text.append(ch, start, length);
                }
            });
            fail("DOCTYPE with an external entity must be rejected, got: " + text);
        } catch (SAXException expected) {
            assertFalse(text.toString().contains(SECRET));
        }
    }

    private void assertDomRejected() throws Exception {
        DocumentBuilder builder = XmlFactory.createDocumentBuilderFactory(false).newDocumentBuilder();
        try {
            Document doc = builder.parse(new InputSource(new StringReader(payload())));
            fail("DOCTYPE with an external entity must be rejected, got: " + doc.getDocumentElement().getTextContent());
        } catch (SAXException expected) {
            // rejected before any entity is resolved
        }
    }
}
