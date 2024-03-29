/* Nextcloud Android Library is available under MIT license
 *
 *   @author Tobias Kaminsky
 *   Copyright (C) 2018 Tobias Kaminsky
 *   Copyright (C) 2018 Nextcloud GmbH
 *
 *   Permission is hereby granted, free of charge, to any person obtaining a copy
 *   of this software and associated documentation files (the "Software"), to deal
 *   in the Software without restriction, including without limitation the rights
 *   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *   copies of the Software, and to permit persons to whom the Software is
 *   furnished to do so, subject to the following conditions:
 *
 *   The above copyright notice and this permission notice shall be included in
 *   all copies or substantial portions of the Software.
 *
 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *   NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 *   BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 *   ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 *   CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *   THE SOFTWARE.
 *
 */

package com.owncloud.android.lib.resources.comments;

import com.owncloud.android.lib.common.OwnCloudClient;
import com.owncloud.android.lib.common.network.WebdavEntry;
import com.owncloud.android.lib.common.operations.RemoteOperation;
import com.owncloud.android.lib.common.operations.RemoteOperationResult;

import org.apache.commons.httpclient.HttpStatus;
import org.apache.jackrabbit.webdav.client.methods.PropPatchMethod;
import org.apache.jackrabbit.webdav.property.DavPropertyNameSet;
import org.apache.jackrabbit.webdav.property.DavPropertySet;
import org.apache.jackrabbit.webdav.property.DefaultDavProperty;
import org.apache.jackrabbit.webdav.xml.Namespace;

import java.io.IOException;

/**
 * Mark all comments for a file as read
 */
public class MarkCommentsAsReadRemoteOperation extends RemoteOperation {
    private static final String COMMENTS_URL = "/comments/files/";

    private final long fileId;

    public MarkCommentsAsReadRemoteOperation(long fileId) {
        this.fileId = fileId;
    }

    @Override
    protected RemoteOperationResult run(OwnCloudClient client) {
        RemoteOperationResult result;
        PropPatchMethod propPatchMethod = null;

        DavPropertySet newProps = new DavPropertySet();
        DavPropertyNameSet removeProperties = new DavPropertyNameSet();

        DefaultDavProperty<String> readMarkerProperty = new DefaultDavProperty<>("oc:readMarker", "",
                Namespace.getNamespace(WebdavEntry.NAMESPACE_OC));
        newProps.add(readMarkerProperty);

        String commentsPath = client.getCommentsUri(fileId);

        try {
            propPatchMethod = new PropPatchMethod(commentsPath, newProps, removeProperties);
            int status = client.executeMethod(propPatchMethod);

            boolean isSuccess = status == HttpStatus.SC_NO_CONTENT || status == HttpStatus.SC_OK ||
                    status == HttpStatus.SC_MULTI_STATUS;

            if (isSuccess) {
                result = new RemoteOperationResult(true, status, propPatchMethod.getResponseHeaders());
            } else {
                client.exhaustResponse(propPatchMethod.getResponseBodyAsStream());
                result = new RemoteOperationResult(false, status, propPatchMethod.getResponseHeaders());
            }
        } catch (IOException e) {
            result = new RemoteOperationResult(e);
        } finally {
            if (propPatchMethod != null) {
                propPatchMethod.releaseConnection();
            }
        }

        return result;
    }
}
