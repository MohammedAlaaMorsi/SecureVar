package io.mohammedalaamorsi.trckq

import kotlin.properties.ReadWriteProperty
import kotlin.reflect.KProperty

fun <T> trckq(
    initialValue: T,
    name: String
): ReadWriteProperty<Any?, T> {
    return TrckqDelegate(initialValue, name)
}

private class TrckqDelegate<T>(
    private var currentValue: T,
    private val name: String
) : ReadWriteProperty<Any?, T> {

    override fun getValue(thisRef: Any?, property: KProperty<*>): T {
        TrckqManager.trigger(
            potName = name,
            accessType = "GET",
            propertyName = property.name,
            className = thisRef?.javaClass?.simpleName ?: "Unknown"
        )
        return currentValue
    }

    override fun setValue(thisRef: Any?, property: KProperty<*>, value: T) {
        TrckqManager.trigger(
            potName = name,
            accessType = "SET",
            propertyName = property.name,
            className = thisRef?.javaClass?.simpleName ?: "Unknown"
        )
        currentValue = value
    }
}
