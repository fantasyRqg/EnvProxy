package com.rqg.envproxy

import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.FragmentActivity
import com.jakewharton.rxbinding3.view.clicks
import io.reactivex.Observable
import io.reactivex.disposables.CompositeDisposable
import java.util.concurrent.TimeUnit

/**
 * * Created by rqg on 2020/3/9.
 */

abstract class BaseActivity : FragmentActivity() {
    protected val destroyComposite = CompositeDisposable()


    override fun onDestroy() {
        super.onDestroy()
        destroyComposite.dispose()
    }


    protected fun View.rxClick(cb: (v: View) -> Unit) {
        val ob = clicks()
            .throttleFirst(500, TimeUnit.MILLISECONDS)
            .subscribe {
                cb(this)
            }

        destroyComposite.add(ob)
    }

    protected fun <T> Observable<T>.dsubscribe(next: (t: T) -> Unit) {
        val d = subscribe {
            next(it)
        }
        destroyComposite.add(d)
    }

    protected fun <T> Observable<T>.dsubscribe(next: (t: T) -> Unit, error: (t: Throwable) -> Unit) {
        val d = subscribe({ next(it) }, { error(it) })
        destroyComposite.add(d)
    }
}
