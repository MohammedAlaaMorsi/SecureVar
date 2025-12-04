package io.mohammedalaamorsi.trckq

import kotlin.reflect.KProperty0
import kotlin.reflect.jvm.isAccessible

// This is the object the developer interacts with
class SecureVarWriter<T>(private val delegate: SecureVarDelegate<T>) {
    fun write(newValue: T, key: WriteKey) {
        delegate.authorizedWrite(newValue, key)
    }
}

// The public function to get the writer from a property reference
fun <T> secureVar(property: KProperty0<T>): SecureVarWriter<T> {
    property.isAccessible = true
    val delegate = property.getDelegate()
        ?.let { it as? SecureVarDelegate<*> }
        ?: throw IllegalArgumentException("Property ${property.name} is not backed by SecureVarDelegate")

    @Suppress("UNCHECKED_CAST")
    val typed = delegate as SecureVarDelegate<T>

    return SecureVarWriter(typed)
}
