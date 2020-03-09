package com.rqg.envproxy

import android.app.Dialog
import android.graphics.drawable.Drawable
import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.Window
import androidx.fragment.app.DialogFragment
import androidx.lifecycle.ViewModelProvider
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import io.reactivex.Observable
import io.reactivex.android.schedulers.AndroidSchedulers
import io.reactivex.disposables.Disposable
import io.reactivex.schedulers.Schedulers
import kotlinx.android.synthetic.main.fragment_app_list.*
import kotlinx.android.synthetic.main.item_app_list.view.*

/**
 * * Created by rqg on 2020/3/9.
 */


class AppListFragment : DialogFragment() {
    companion object {
        private const val TAG = "AppListFragment"
    }

    private var disposable: Disposable? = null

    private val mAdapter by lazy { MyAdapter(this) }

    internal val vm by lazy { ViewModelProvider(requireActivity()).get(VM::class.java) }


    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        val onCreateDialog = super.onCreateDialog(savedInstanceState)
        onCreateDialog.window.requestFeature(Window.FEATURE_NO_TITLE)
        return onCreateDialog
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.fragment_app_list, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        val pm = requireContext().packageManager
        disposable = Observable.just(1)
            .subscribeOn(Schedulers.io())
            .flatMap {
                val map = pm.getInstalledApplications(0)
                Observable.fromIterable(map)
            }
            .map {
                AppInfo(
                    pm.getApplicationLabel(it),
                    it.packageName,
                    pm.getApplicationIcon(it)
                )
            }
            .observeOn(AndroidSchedulers.mainThread())
            .subscribe({
                mAdapter.data.add(it)
                mAdapter.notifyItemInserted(mAdapter.data.size)
            }, {
                Log.e(TAG, "onViewCreated: ", it)
            })

        mAdapter.data.add(AppInfo("All", "", resources.getDrawable(R.drawable.ic_launcher_background, null)))
        app_list.adapter = mAdapter
        app_list.layoutManager = LinearLayoutManager(context, LinearLayoutManager.VERTICAL, false)
    }

    override fun onDestroyView() {
        disposable?.dispose()
        super.onDestroyView()
    }
}


data class AppInfo(
    val name: CharSequence,
    val packageName: String,
    var icon: Drawable
)


private class MyAdapter(private val appListFragment: AppListFragment) : RecyclerView.Adapter<MyVH>() {
    val data = mutableListOf<AppInfo>()

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): MyVH {
        return MyVH(LayoutInflater.from(parent.context).inflate(R.layout.item_app_list, parent, false))
    }

    override fun getItemCount(): Int {
        return data.size
    }

    override fun onBindViewHolder(h: MyVH, position: Int) {
        val app = data[position]
        h.appIcon.setImageDrawable(app.icon)
        h.appName.text = app.name

        h.itemView.setOnClickListener {
            appListFragment.vm.changeApp.postValue(app)
            appListFragment.dismiss()
        }
    }
}

private class MyVH(itemView: View) : RecyclerView.ViewHolder(itemView) {
    val appIcon = itemView.app_icon
    val appName = itemView.app_name
}