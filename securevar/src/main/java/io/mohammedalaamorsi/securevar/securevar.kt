package io.mohammedalaamorsi.securevar

import kotlin.properties.ReadWriteProperty
import kotlin.reflect.KProperty

fun <T> securevar(
    initialValue: T,
    name: String
): ReadWriteProperty<Any?, T> {
    return BasicSecureVarDelegate(initialValue, name)
}

private class BasicSecureVarDelegate<T>(
    private var currentValue: T,
    private val name: String
) : ReadWriteProperty<Any?, T> {

    override fun getValue(thisRef: Any?, property: KProperty<*>): T {
        SecureVarManager.trigger(
            potName = name,
            accessType = "GET",
            propertyName = property.name,
            className = thisRef?.javaClass?.simpleName ?: "Unknown"
        )
        return currentValue
    }

    override fun setValue(thisRef: Any?, property: KProperty<*>, value: T) {
        SecureVarManager.trigger(
            potName = name,
            accessType = "SET",
            propertyName = property.name,
            className = thisRef?.javaClass?.simpleName ?: "Unknown"
        )
        currentValue = value
    }
}
