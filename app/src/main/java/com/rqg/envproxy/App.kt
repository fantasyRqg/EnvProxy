package com.rqg.envproxy

import android.app.Application

/**
 * * Created by rqg on 2018/11/20.
 */


class App : Application() {
    companion object {
        fun get() = INSTANCE
        private lateinit var INSTANCE: App

    }


    override fun onCreate() {
        super.onCreate()
        INSTANCE = this
    }
}