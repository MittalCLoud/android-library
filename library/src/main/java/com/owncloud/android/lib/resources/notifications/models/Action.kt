/*  Nextcloud Android Library is available under MIT license
 *
 *   @author Andy Scherzinger
 *   Copyright (C) 2017 Andy Scherzinger
 *   Copyright (C) 2017 Nextcloud GmbH
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
package com.owncloud.android.lib.resources.notifications.models

/**
 * Action data model.
 */
class Action() {
    /**
     * Translated short label of the action/button that should be presented to the user.
     */
    @JvmField
    var label: String? = null

    /**
     * A link that should be followed when the action is performed/clicked.
     */
    @JvmField
    var link: String? = null

    /**
     * HTTP method that should be used for the request against the link: GET, POST, DELETE.
     */
    @JvmField
    var type: String? = null

    /**
     * If the action is the primary action for the notification or not.
     */
    @JvmField
    var primary = false

    constructor(label: String?, link: String?, type: String?, primary: Boolean) : this() {
        this.label = label
        this.link = link
        this.type = type
        this.primary = primary
    }
}
