/*
 * Copyright (C) 2014 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.server.ethernet;

import android.content.Context;
import android.content.pm.PackageManager;
import android.net.IEthernetManager;
import android.net.IEthernetServiceListener;
import android.net.IpConfiguration;
import android.net.IpConfiguration.IpAssignment;
import android.net.IpConfiguration.ProxySettings;
/* Dual Ethernet Changes Start */
import android.net.LinkProperties;
import android.net.NetworkInfo;
/* Dual Ethernet Changes End */
import android.net.ProxyInfo;
import android.os.Binder;
import android.os.IBinder;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.INetworkManagementService;
import android.os.RemoteCallbackList;
import android.os.RemoteException;
import android.provider.Settings;
import android.os.ServiceManager;
import android.os.SystemProperties;
import android.util.Log;
import android.util.PrintWriterPrinter;

import com.android.internal.util.IndentingPrintWriter;

import java.lang.Integer;
import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * EthernetServiceImpl handles remote Ethernet operation requests by implementing
 * the IEthernetManager interface.
 *
 * @hide
 */
public class EthernetServiceImpl extends IEthernetManager.Stub {
    private static final String TAG = "EthernetServiceImpl";

    private final Context mContext;
    private final EthernetConfigStore mEthernetConfigStore;
    private final INetworkManagementService mNMService;
    private final AtomicBoolean mStarted = new AtomicBoolean(false);
    /* Dual Ethernet Changes Start */
    private final AtomicBoolean mPluggedInEthernetStarted = new AtomicBoolean(false);
    private IpConfiguration mIpConfiguration;

    private IpConfiguration mPluggedInEthernetIpConfiguration;
    /* Dual Ethernet Changes End */
    private ProxyInfo MyHttpProxy;
    private Handler mHandler;
    /* Dual Ethernet Changes Start */
    private Handler  mPluggedinEthHandler;
    /* Dual Ethernet Changes End */
    private final EthernetNetworkFactory mTracker;
    /* Dual Ethernet Changes Start */
    private final PluggedinEthernetNetworkFactory  mEth1Tracker;
    /* Dual Ethernet Changes End */
    private String Proxyhost;
    private String Proxyport;
    /* Dual Ethernet Changes Start */
    private String PluggedInEthernetProxyhost;
    private String PluggedInEthernetProxyport;
    /* Dual Ethernet Changes Start */
    private final RemoteCallbackList<IEthernetServiceListener> mListeners =
            new RemoteCallbackList<IEthernetServiceListener>();

    /* Dual Ethernet Changes Start */
    private final RemoteCallbackList<IEthernetServiceListener> mEth1Listeners =
            new RemoteCallbackList<IEthernetServiceListener>();
    /* Dual Ethernet Changes End */
    public EthernetServiceImpl(Context context) {
        mContext = context;
        Log.i(TAG, "Creating EthernetConfigStore");
        mEthernetConfigStore = new EthernetConfigStore();
        mIpConfiguration = mEthernetConfigStore.readIpAndProxyConfigurations();

        Log.i(TAG, "Read stored IP configuration: " + mIpConfiguration);
        Log.i(TAG, "Get proxy info from system properties");
        Proxyhost = SystemProperties.get("persist.ethernet.proxyhost", "");
        Log.i(TAG, "Proxyhost: --" + Proxyhost);
        Proxyport = SystemProperties.get("persist.ethernet.proxyport", "");
        Log.i(TAG, "Proxyport: --" + Proxyport);
        if (!Proxyhost.equals("") && !Proxyport.equals("")){
            mIpConfiguration.setProxySettings(ProxySettings.STATIC);
            MyHttpProxy = new ProxyInfo(Proxyhost,Integer.parseInt(Proxyport),null);
            mIpConfiguration.setHttpProxy(MyHttpProxy);
        }
        Log.i(TAG, "New IP Configuration: " + mIpConfiguration);
        //Proxy settings for PluggedIn Ethernet Starts
        mPluggedInEthernetIpConfiguration =
                        mEthernetConfigStore.readPluggedInEthernetIpAndProxyConfigurations();

        Log.i(TAG, "PluggedIn Ethernet IPConfiguration: " + mPluggedInEthernetIpConfiguration);
        Log.i(TAG, "Get proxy info from system properties");

        PluggedInEthernetProxyhost = SystemProperties.get("persist.ethernet.pluggedin.proxyhost", "");
        PluggedInEthernetProxyport = SystemProperties.get("persist.ethernet.pluggedin.proxyport", "");

        Log.i(TAG, "PluggedInEthernetProxyhost: --" + PluggedInEthernetProxyhost);
        Log.i(TAG, "PluggedInEthernetProxyport: --" + PluggedInEthernetProxyport);

        if (!PluggedInEthernetProxyport.equals("") && !PluggedInEthernetProxyport.equals("")){
            mPluggedInEthernetIpConfiguration.setProxySettings(ProxySettings.STATIC);
            MyHttpProxy = new ProxyInfo(Proxyhost,Integer.parseInt(Proxyport),null);
            mPluggedInEthernetIpConfiguration.setHttpProxy(MyHttpProxy);
        }
        Log.i(TAG, "PluggedIn Ethernet IPConfiguration: " + mPluggedInEthernetIpConfiguration);
        //Proxy settings for PluggedIn Ethernet Ends
        IBinder b = ServiceManager.getService(Context.NETWORKMANAGEMENT_SERVICE);
        mNMService = INetworkManagementService.Stub.asInterface(b);

        mTracker = new EthernetNetworkFactory(mListeners);
        /* Dual Ethernet Changes Start */
        mEth1Tracker = new PluggedinEthernetNetworkFactory(mEth1Listeners);
        /* Dual Ethernet Changes End */
    }

    private void enforceAccessPermission() {
        mContext.enforceCallingOrSelfPermission(
                android.Manifest.permission.ACCESS_NETWORK_STATE,
                "EthernetService");
    }

    private void enforceConnectivityInternalPermission() {
        mContext.enforceCallingOrSelfPermission(
                android.Manifest.permission.CONNECTIVITY_INTERNAL,
                "ConnectivityService");
    }

    public void start() {
        Log.i(TAG, "Starting Ethernet service");

        HandlerThread handlerThread = new HandlerThread("EthernetServiceThread");
        handlerThread.start();
        mHandler = new Handler(handlerThread.getLooper());

        mTracker.start(mContext, mHandler);
        /* Dual Ethernet Changes Start */
        HandlerThread PluggedinEthhandlerThread = new HandlerThread("PluggedinEthernetThread");
        PluggedinEthhandlerThread.start();
        mPluggedinEthHandler = new Handler(PluggedinEthhandlerThread.getLooper());

        mEth1Tracker.start(mContext,mPluggedinEthHandler);
        mPluggedInEthernetStarted.set(true);
        /* Dual Ethernet Changes End */
        mStarted.set(true);
    }

    /**
     * Get Ethernet configuration
     * @return the Ethernet Configuration, contained in {@link IpConfiguration}.
     */
    @Override
    public IpConfiguration getConfiguration() {
        enforceAccessPermission();

        synchronized (mIpConfiguration) {
            return new IpConfiguration(mIpConfiguration);
        }
    }

    /**
     * Set Ethernet configuration
     */
    @Override
    public void setConfiguration(IpConfiguration config) {
        if (!mStarted.get()) {
            Log.w(TAG, "System isn't ready enough to change ethernet configuration");
        }

        enforceConnectivityInternalPermission();

        synchronized (mIpConfiguration) {
            mEthernetConfigStore.writeIpAndProxyConfigurations(config);

            // TODO: this does not check proxy settings, gateways, etc.
            // Fix this by making IpConfiguration a complete representation of static configuration.
            if (!config.equals(mIpConfiguration)) {
                mIpConfiguration = new IpConfiguration(config);
                mTracker.stop();
                mTracker.start(mContext, mHandler);
            }
        }
    }

    /**
     * Indicates whether the system currently has one or more
     * Ethernet interfaces.
     */
    @Override
    public boolean isAvailable() {
        enforceAccessPermission();
        return mTracker.isTrackingInterface();
    }

    /**
     * Addes a listener.
     * @param listener A {@link IEthernetServiceListener} to add.
     */
    public void addListener(IEthernetServiceListener listener) {
        if (listener == null) {
            throw new IllegalArgumentException("listener must not be null");
        }
        enforceAccessPermission();
        mListeners.register(listener);
    }

    /**
     * Removes a listener.
     * @param listener A {@link IEthernetServiceListener} to remove.
     */
    public void removeListener(IEthernetServiceListener listener) {
        if (listener == null) {
            throw new IllegalArgumentException("listener must not be null");
        }
        enforceAccessPermission();
        mListeners.unregister(listener);
    }

    @Override
    protected void dump(FileDescriptor fd, PrintWriter writer, String[] args) {
        final IndentingPrintWriter pw = new IndentingPrintWriter(writer, "  ");
        if (mContext.checkCallingOrSelfPermission(android.Manifest.permission.DUMP)
                != PackageManager.PERMISSION_GRANTED) {
            pw.println("Permission Denial: can't dump EthernetService from pid="
                    + Binder.getCallingPid()
                    + ", uid=" + Binder.getCallingUid());
            return;
        }

        pw.println("Current Ethernet state: ");
        pw.increaseIndent();
        mTracker.dump(fd, pw, args);
        pw.decreaseIndent();

        pw.println();
        pw.println("Stored Ethernet configuration: ");
        pw.increaseIndent();
        pw.println(mIpConfiguration);
        pw.decreaseIndent();

        pw.println("Handler:");
        pw.increaseIndent();
        mHandler.dump(new PrintWriterPrinter(pw), "EthernetServiceImpl");
        pw.decreaseIndent();
    }

    @Override
    public void reconnect() {
        enforceConnectivityInternalPermission();

        mTracker.start(mContext, mHandler);
    }

    @Override
    public void teardown() {
        enforceConnectivityInternalPermission();

        mTracker.stop();
    }

    /**
     * Gets LAN Ethernet Link Properties.
     * @return the Ethernet Configuration, contained in {@link IpConfiguration}.
     */
    public LinkProperties getEthernetLinkProperties() {
        enforceAccessPermission();
        return mTracker.getLinkProperties();
    }

    /**
     * Return the NetworkInfo of the LAN Ethernet
     * @return the NetworkInfo, contained in {@link NetworkInfo}.
     */
    public NetworkInfo getEthernetNetworkInfo() {
        enforceAccessPermission();
        return mTracker.getNetworkInfo();
    }

    /**
     * Addes a listener.
     * @param listener A {@link IEthernetServiceListener} to add.
     * Indicates whether the PluggedIn Ethernet is connected (ETH1).
     */
    @Override
    public boolean isPluggedInEthAvailable() {
        enforceAccessPermission();
        return mEth1Tracker.isTrackingInterface();
    }

    @Override
    public void connectPluggedinEth() {
        enforceConnectivityInternalPermission();
        mEth1Tracker.start(mContext,mPluggedinEthHandler);
    }

    @Override
    public void teardownPluggedinEth() {
        enforceConnectivityInternalPermission();
        mEth1Tracker.stop();
    }

    public void addPluggedinEthListener(IEthernetServiceListener listener) {
        if (listener == null) {
            throw new IllegalArgumentException("listener must not be null");
        }
        enforceAccessPermission();
        mEth1Listeners.register(listener);
    }

    /**
     * Removes a listener.
     * @param listener A {@link IEthernetServiceListener} to remove.
     */
    public void removePluggedinEthListener(IEthernetServiceListener listener) {
        if (listener == null) {
            throw new IllegalArgumentException("listener must not be null");
        }
        enforceAccessPermission();
        mEth1Listeners.unregister(listener);
    }

    /**
     * Gets PluggedIn Ethernet Link Properties.
     * @return the Ethernet Configuration, contained in {@link IpConfiguration}.
     */
    public LinkProperties getPluggedinLinkProperties() {
        enforceAccessPermission();
        return mEth1Tracker.getLinkProperties();
    }

    /**
     * Return the NetworkInfo of the PluggedIn Ethernet
     * @return the NetworkInfo, contained in {@link NetworkInfo}.
     */
    public NetworkInfo getPluggedinNetworkInfo() {
        enforceAccessPermission();
        return mEth1Tracker.getNetworkInfo();
    }

    /**
     * Get PluggedInEthernet configuration
     * @return the Ethernet Configuration, contained in {@link IpConfiguration}.
     */
    @Override
    public IpConfiguration getPluggedInEthernetConfiguration() {
        enforceAccessPermission();

        synchronized (mPluggedInEthernetIpConfiguration) {
            return new IpConfiguration(mPluggedInEthernetIpConfiguration);
        }
    }

    /**
     * Set PluggedInEthernet configuration
     */
    @Override
    public void setPluggedInEthernetConfiguration(IpConfiguration config) {
        if (!mPluggedInEthernetStarted.get()) {
            Log.w(TAG, "System isn't ready enough to change ethernet configuration");
        }
        enforceConnectivityInternalPermission();
        synchronized (mPluggedInEthernetIpConfiguration) {
            mEthernetConfigStore.writePluggedInEthernetIpAndProxyConfigurations(config);

            // TODO: this does not check proxy settings, gateways, etc.
            // Fix this by making IpConfiguration a complete representation of static configuration.
            if (!config.equals(mPluggedInEthernetIpConfiguration)) {
                mPluggedInEthernetIpConfiguration = new IpConfiguration(config);
                mEth1Tracker.stop();
                mEth1Tracker.start(mContext, mHandler);
            }
        }
    }
    /* Dual Ethernet Changes End */
 }
