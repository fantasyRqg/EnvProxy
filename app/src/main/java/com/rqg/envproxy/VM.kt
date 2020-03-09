package com.rqg.envproxy

import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel

/**
 * * Created by rqg on 2020/3/9.
 */
class VM : ViewModel() {
    val changeApp by lazy { MutableLiveData<AppInfo>() }
}