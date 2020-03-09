package com.rqg.envproxy

import io.reactivex.Observable
import io.reactivex.subjects.PublishSubject

/**
 * * Created by rqg on 2020/3/9.
 */
object ServiceBus {

    private val publisher = PublishSubject.create<Int>()

    fun publish(event: Int) {
        publisher.onNext(event)
    }

    fun listen(): Observable<Int> = publisher
}