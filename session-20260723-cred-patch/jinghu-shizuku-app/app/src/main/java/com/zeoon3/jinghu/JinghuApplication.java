package com.zeoon3.jinghu;

import android.app.Application;

import com.google.android.material.color.DynamicColors;

/** Applies Material You dynamic color to every Activity when the platform supports it. */
public final class JinghuApplication extends Application {
    @Override
    public void onCreate() {
        super.onCreate();
        DynamicColors.applyToActivitiesIfAvailable(this);
    }
}
