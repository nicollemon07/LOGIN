from flask import Flask, render_template, request, redirect, url_for, session, flash
import mysql.connector
from mysql.connector import Error
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message   # ✅ importar Flask-Mail
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'secreto123')

# ---------------- CONFIGURACIÓN DE FLASK-MAIL ----------------
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'nicollmon2007@gmail.com'
app.config['MAIL_PASSWORD'] = 'qeds kbtp ragw qvqj'
app.config['MAIL_DEFAULT_SENDER'] = ('Soporte App', 'nicollmon2007@gmail.com')

mail = Mail(app)
# --------------------------------------------------------------


# Conexión a MySQL
def get_db_connection():
    return mysql.connector.connect(
        host=os.environ.get('DB_HOST', 'localhost'),
        user=os.environ.get('DB_USER', 'root'),
        password=os.environ.get('DB_PASS', ''),
        database=os.environ.get('DB_NAME', 'flask_login'),
        port=int(os.environ.get('DB_PORT', 3306))
    )

# -------------------- HOME --------------------
@app.route('/')
def home():
    if 'user_id' in session:
        return render_template('home.html', nombre=session.get('user'), rol=session.get('rol'))
    return redirect(url_for('login'))

# -------------------- REGISTRO --------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nombre = request.form['nombre']
        correo = request.form['correo']
        password_raw = request.form['password']
        password = generate_password_hash(password_raw)
        rol = request.form['rol']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT id FROM usuarios WHERE correo = %s", (correo,))
            if cursor.fetchone():
                flash("El correo ya está registrado", "danger")
                return redirect(url_for('register'))

            cursor.execute(
                "INSERT INTO usuarios (nombre, correo, password, rol) VALUES (%s, %s, %s, %s)",
                (nombre, correo, password, rol)
            )
            conn.commit()
            flash("Usuario registrado correctamente. Ahora inicia sesión.", "success")
            return redirect(url_for('login'))
        except Error as e:
            flash("Error al registrar usuario: " + str(e), "danger")
        finally:
            cursor.close()
            conn.close()

    return render_template('register.html')

# -------------------- LOGIN --------------------
from datetime import datetime, timedelta

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        correo = request.form['correo']
        password = request.form['password']
        rol = request.form['rol']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("SELECT * FROM usuarios WHERE correo = %s", (correo,))
            user = cursor.fetchone()

            if user:
                # 🚫 Verificar si está inactivo
                if user['estado'] == 'inactivo':
                    flash("Tu cuenta está desactivada. Contacta con un administrador.", "danger")
                    return redirect(url_for('login'))

                # 🚫 Verificar intentos fallidos
                if user['intentos_fallidos'] >= 3:
                    if user['ultimo_intento'] and datetime.now() - user['ultimo_intento'] < timedelta(minutes=5):
                        flash("Cuenta bloqueada por demasiados intentos fallidos. Intenta de nuevo en 5 minutos.", "danger")
                        return redirect(url_for('login'))
                    else:
                        # ⏳ Reiniciar después de 5 min
                        cursor.execute("UPDATE usuarios SET intentos_fallidos = 0 WHERE id = %s", (user['id'],))
                        conn.commit()

                # 🔑 Validar contraseña y rol
                if check_password_hash(user['password'], password):
                    if user['rol'] != rol:
                        flash("El rol seleccionado no coincide con tu cuenta.", "danger")
                        return redirect(url_for('login'))

                    # ✅ Reiniciar intentos fallidos
                    cursor.execute("UPDATE usuarios SET intentos_fallidos = 0 WHERE id = %s", (user['id'],))
                    conn.commit()

                    # Guardar sesión
                    session['user_id'] = user['id']
                    session['user'] = user['nombre']
                    session['rol'] = user['rol']

                    flash("Inicio de sesión exitoso", "success")

                    if user['rol'] == 'admin':
                        return redirect(url_for('admin_dashboard'))
                    else:
                        return redirect(url_for('home'))

                else:
                    # ❌ Contraseña incorrecta → sumar intento
                    cursor.execute(
                        "UPDATE usuarios SET intentos_fallidos = intentos_fallidos + 1, ultimo_intento = %s WHERE id = %s",
                        (datetime.now(), user['id'])
                    )
                    conn.commit()
                    flash("Contraseña incorrecta", "danger")
                    return redirect(url_for('login'))

            flash("Correo no encontrado", "danger")
            return redirect(url_for('login'))

        finally:
            cursor.close()
            conn.close()

    return render_template('login.html')



# -------------------- LOGOUT --------------------
@app.route('/logout')
def logout():
    session.clear()
    flash("Sesión cerrada", "info")
    return redirect(url_for('login'))

# -------------------- PERFIL --------------------
@app.route('/perfil')
def perfil():
    if 'user_id' not in session:
        flash("Debes iniciar sesión para ver tu perfil.", "warning")
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Obtener usuario
    cursor.execute("SELECT * FROM usuarios WHERE id = %s", (session['user_id'],))
    usuario = cursor.fetchone()

    # Obtener postres
    cursor.execute("SELECT * FROM postres")
    postres = cursor.fetchall()

    cursor.close()
    conn.close()

    if not usuario:
        flash("Usuario no encontrado. Vuelve a iniciar sesión.", "danger")
        session.clear()
        return redirect(url_for('login'))

    return render_template('perfil.html', usuario=usuario, postres=postres)



# -------------------- ELIMINAR CUENTA --------------------
# -------------------- ELIMINAR CUENTA (soft delete) --------------------
@app.route('/eliminar_cuenta', methods=['POST'])
def eliminar_cuenta():
    if 'user_id' not in session:
        flash("Debes iniciar sesión para eliminar tu cuenta.", "warning")
        return redirect(url_for('login'))

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE usuarios SET estado = 'inactivo' WHERE id = %s", (user_id,))
    conn.commit()
    cursor.close()
    conn.close()

    # Cerramos sesión después de desactivar
    session.clear()
    flash("Tu cuenta ha sido desactivada. Contacta con un administrador si deseas reactivarla.", "info")
    return redirect(url_for('login'))


# -------------------- ACTUALIZAR PERFIL --------------------
@app.route('/actualizar_perfil', methods=['POST'])
def actualizar_perfil():
    if 'user_id' not in session:
        flash("Debes iniciar sesión para actualizar tu perfil.", "warning")
        return redirect(url_for('login'))

    nombre = request.form['nombre']
    correo = request.form['correo']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE usuarios SET nombre=%s, correo=%s WHERE id=%s",
                   (nombre, correo, session['user_id']))
    conn.commit()
    cursor.close()
    conn.close()

    # Actualizamos también la sesión para reflejar el cambio
    session['user'] = nombre  

    flash("Perfil actualizado correctamente ✅", "success")
    return redirect(url_for('perfil'))


@app.route('/update_user', methods=['POST'])
def update_user():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    nombre = request.form['nombre']
    correo = request.form['correo']

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "UPDATE usuarios SET nombre = %s, correo = %s WHERE id = %s",
            (nombre, correo, session['user_id'])
        )
        conn.commit()
        session['user'] = nombre
        flash("Datos actualizados correctamente", "success")
    except Error as e:
        flash("Error al actualizar usuario: " + str(e), "danger")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('perfil'))

@app.route('/delete_user', methods=['POST'])
def delete_user():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM usuarios WHERE id = %s", (session['user_id'],))
        conn.commit()
        session.clear()
        flash("Cuenta eliminada correctamente", "info")
    except Error as e:
        flash("Error al eliminar usuario: " + str(e), "danger")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('login'))

# -------------------- OLVIDÉ PASSWORD --------------------
import random
import datetime

@app.route('/olvide-password', methods=['GET', 'POST'])
def olvide_password():
    if request.method == 'POST':
        correo = request.form['correo']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM usuarios WHERE correo = %s", (correo,))
        user = cursor.fetchone()

        if user:
            # ✅ Generar código OTP de 6 dígitos
            codigo = str(random.randint(100000, 999999))
            expiracion = datetime.datetime.now() + datetime.timedelta(minutes=10)

            # Guardar en BD
            cursor.execute("""
                INSERT INTO codigos_reset (user_id, codigo, expiracion, usado)
                VALUES (%s, %s, %s, %s)
            """, (user['id'], codigo, expiracion, False))
            conn.commit()

            # Enviar correo con el código
            msg = Message("Código de recuperación",
                          recipients=[correo])
            msg.body = f"""
Hola {user['nombre']},

Tu código de recuperación es: {codigo}

Este código expirará en 10 minutos.
"""
            mail.send(msg)

            flash("✅ Te hemos enviado un código a tu correo", "success")
            session['reset_user_id'] = user['id']  # Guardamos el user_id en la sesión
            return redirect(url_for('validar_codigo'))

        else:
            flash("❌ El correo no está registrado", "danger")

        cursor.close()
        conn.close()

    return render_template('olvide_password.html')

@app.route('/validar-codigo', methods=['GET', 'POST'])
def validar_codigo():
    if 'reset_user_id' not in session:
        flash("Solicitud inválida", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        codigo_ingresado = request.form['codigo']
        user_id = session['reset_user_id']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT * FROM codigos_reset 
            WHERE user_id = %s AND codigo = %s AND usado = FALSE 
            ORDER BY id DESC LIMIT 1
        """, (user_id, codigo_ingresado))
        registro = cursor.fetchone()

        if registro:
            # Validar expiración
            if registro['expiracion'] < datetime.datetime.now():
                flash("❌ El código ha expirado", "danger")
                return redirect(url_for('olvide_password'))

            # Marcar como usado
            cursor.execute("UPDATE codigos_reset SET usado = TRUE WHERE id = %s", (registro['id'],))
            conn.commit()

            flash("✅ Código validado. Ahora puedes restablecer tu contraseña", "success")
            return redirect(url_for('reset_password', id=user_id))

        else:
            flash("❌ Código inválido", "danger")

        cursor.close()
        conn.close()

    return render_template('validar_codigo.html')


@app.route('/reset-password/<int:id>', methods=['GET', 'POST'])
def reset_password(id):
    if request.method == 'POST':
        nueva_pass = request.form['password']
        hashed_pass = generate_password_hash(nueva_pass)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE usuarios SET password = %s WHERE id = %s", (hashed_pass, id))
        conn.commit()
        cursor.close()
        conn.close()

        flash("🔑 Tu contraseña fue restablecida con éxito. Inicia sesión.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html')


# -------------------- ADMIN --------------------
@app.route('/admin')
def admin_dashboard():
    if 'rol' in session and session['rol'] == 'admin':
        return render_template('admin.html', nombre=session['user'])
    else:
        flash("Acceso denegado. Solo administradores.", "danger")
        return redirect(url_for('home'))

# -------------------- GESTIÓN DE USUARIOS (ADMIN) --------------------
@app.route('/admin/usuarios')
def gestionar_usuarios():
    if 'rol' not in session or session['rol'] != 'admin':
        flash("Acceso denegado", "danger")
        return redirect(url_for('home'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, nombre, correo, rol, estado FROM usuarios")
    usuarios = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('gestionar_usuarios.html', usuarios=usuarios)


@app.route('/admin/usuarios/editar/<int:id>', methods=['GET', 'POST'])
def editar_usuario(id):
    if 'rol' not in session or session['rol'] != 'admin':
        flash("Acceso denegado", "danger")
        return redirect(url_for('home'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == 'POST':
        nombre = request.form['nombre']
        correo = request.form['correo']
        rol = request.form['rol']
        cursor.execute("UPDATE usuarios SET nombre=%s, correo=%s, rol=%s WHERE id=%s", (nombre, correo, rol, id))
        conn.commit()
        cursor.close()
        conn.close()
        flash("Usuario actualizado correctamente", "success")
        return redirect(url_for('gestionar_usuarios'))

    cursor.execute("SELECT * FROM usuarios WHERE id=%s", (id,))
    usuario = cursor.fetchone()
    cursor.close()
    conn.close()
    return render_template('editar_usuario.html', usuario=usuario)

@app.route('/admin/usuarios/desactivar/<int:id>', methods=['POST'])
def desactivar_usuario(id):
    if 'rol' not in session or session['rol'] != 'admin':
        flash("Acceso denegado", "danger")
        return redirect(url_for('home'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE usuarios SET estado = 'inactivo' WHERE id=%s", (id,))
    conn.commit()
    cursor.close()
    conn.close()
    flash("Usuario desactivado correctamente", "info")
    return redirect(url_for('gestionar_usuarios'))

@app.route('/admin/usuarios/activar/<int:id>', methods=['POST'])
def activar_usuario(id):
    if 'rol' not in session or session['rol'] != 'admin':
        flash("Acceso denegado", "danger")
        return redirect(url_for('home'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE usuarios SET estado = 'activo' WHERE id=%s", (id,))
    conn.commit()
    cursor.close()
    conn.close()
    flash("Usuario activado correctamente ✅", "success")
    return redirect(url_for('gestionar_usuarios'))


# 🔹 Actualizar usuario desde admin
@app.route('/admin/update_user/<int:id>', methods=['POST'])
def admin_update_user(id):
    if 'rol' not in session or session['rol'] != 'admin':
        flash("Acceso denegado", "danger")
        return redirect(url_for('home'))

    nombre = request.form['nombre']
    correo = request.form['correo']
    rol = request.form['rol']

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "UPDATE usuarios SET nombre = %s, correo = %s, rol = %s WHERE id = %s",
            (nombre, correo, rol, id)
        )
        conn.commit()
        flash("Usuario actualizado correctamente", "success")
    except Error as e:
        flash("Error al actualizar usuario: " + str(e), "danger")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('admin_dashboard'))

@app.route('/vitrina')
def vitrina():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, nombre, precio, imagen_url FROM postres")
    postres = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('vitrina.html', postres=postres)


@app.route("/agregar/<int:id_postre>")
def agregar_carrito(id_postre):
    carrito = session.get("carrito", [])

    # Buscar el postre en la BD
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, nombre, precio, imagen_url FROM postres WHERE id = %s", (id_postre,))
    postre = cur.fetchone()
    cur.close()
    conn.close()

    if postre:
        # Revisar si ya existe en el carrito
        for item in carrito:
            if item["id"] == postre[0]:
                item["cantidad"] += 1   # 👈 Incrementar cantidad
                break
        else:
            # Si no existe, lo agregamos con cantidad = 1
            carrito.append({
                "id": postre[0],
                "nombre": postre[1],
                "precio": float(postre[2]),
                "imagen": postre[3],
                "cantidad": 1  # 👈 Aquí agregamos la clave cantidad
            })

    session["carrito"] = carrito
    return redirect(url_for("ver_carrito"))


@app.route('/carrito')
def ver_carrito():
    carrito = session.get("carrito", [])
    total = sum(item["precio"] * item["cantidad"] for item in carrito)
    return render_template("carrito.html", carrito=carrito, total=total)


@app.route('/eliminar/<int:id_postre>', methods=["POST"])
def eliminar_carrito(id_postre):
    carrito = session.get("carrito", [])

    # Filtramos para quitar el producto con ese id
    carrito = [item for item in carrito if item["id"] != id_postre]

    # Guardamos de nuevo el carrito en la sesión
    session["carrito"] = carrito
    session.modified = True

    return redirect(url_for("ver_carrito"))

from datetime import datetime   # ✅ Importación corregida

from datetime import datetime

from datetime import datetime

@app.route("/factura")
def factura():
    carrito = session.get("carrito", [])
    total = sum(item["precio"] * item["cantidad"] for item in carrito)
    fecha = datetime.now().strftime("%d/%m/%Y %H:%M")

    usuario = None
    if 'user_id' in session:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT nombre, correo FROM usuarios WHERE id = %s", (session['user_id'],))
        usuario = cur.fetchone()
        cur.close()
        conn.close()

    # ✅ Agrega prints para depurar en consola
    print("🛒 Carrito:", carrito)
    print("👤 Usuario:", usuario)
    print("💰 Total:", total)
    print("🕒 Fecha:", fecha)

    return render_template("factura.html", carrito=carrito, usuario=usuario, total=total, fecha=fecha)

@app.route('/mis-pedidos')
def mis_pedidos():
    if 'user_id' not in session:
        flash("Debes iniciar sesión para ver tus pedidos", "warning")
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Traer pedidos del usuario
    cursor.execute("""
        SELECT p.id, p.total, p.fecha, COUNT(dp.id) AS cantidad_productos
        FROM pedidos p
        JOIN detalle_pedido dp ON dp.pedido_id = p.id
        WHERE p.user_id = %s
        GROUP BY p.id
        ORDER BY p.fecha DESC
    """, (session['user_id'],))
    pedidos = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("mis_pedidos.html", pedidos=pedidos)

# ➕ Incrementar cantidad
@app.route('/carrito/incrementar/<int:id_postre>', methods=['POST'])
def incrementar_cantidad(id_postre):
    carrito = session.get("carrito", [])
    for item in carrito:
        if item["id"] == id_postre:
            item["cantidad"] += 1
            break
    session["carrito"] = carrito
    session.modified = True
    return redirect(url_for("ver_carrito"))

# ➖ Disminuir cantidad
@app.route('/carrito/disminuir/<int:id_postre>', methods=['POST'])
def disminuir_cantidad(id_postre):
    carrito = session.get("carrito", [])
    for item in carrito:
        if item["id"] == id_postre:
            if item["cantidad"] > 1:
                item["cantidad"] -= 1
            break
    session["carrito"] = carrito
    session.modified = True
    return redirect(url_for("ver_carrito"))

# ------------------ CRUD DE PRODUCTOS ------------------

@app.route("/admin/productos")
def admin_productos():
    if session.get("rol") != "admin":
        flash("Acceso denegado.", "danger")
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM postres")
    postres = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template("admin/productos.html", postres=postres)


@app.route("/admin/productos/agregar", methods=["GET", "POST"])
def agregar_producto():
    if session.get("rol") != "admin":
        flash("Acceso denegado.", "danger")
        return redirect(url_for("login"))

    if request.method == "POST":
        nombre = request.form["nombre"]
        precio = request.form["precio"]
        stock = request.form["stock"]

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO postres (nombre, precio, stock) VALUES (%s, %s, %s)",
                       (nombre, precio, stock))
        conn.commit()
        cursor.close()
        conn.close()

        flash("Producto agregado exitosamente", "success")
        return redirect(url_for("admin_productos"))

    return render_template("admin/agregar_producto.html")


@app.route("/admin/productos/editar/<int:id>", methods=["GET", "POST"])
def editar_producto(id):
    if session.get("rol") != "admin":
        flash("Acceso denegado.", "danger")
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == "POST":
        nombre = request.form["nombre"]
        precio = request.form["precio"]
        stock = request.form["stock"]

        cursor.execute("UPDATE postres SET nombre=%s, precio=%s, stock=%s WHERE id=%s",
                       (nombre, precio, stock, id))
        conn.commit()
        cursor.close()
        conn.close()

        flash("Producto actualizado", "success")
        return redirect(url_for("admin_productos"))

    cursor.execute("SELECT * FROM postres WHERE id=%s", (id,))
    postre = cursor.fetchone()
    cursor.close()
    conn.close()

    return render_template("admin/editar_producto.html", postre=postre)


@app.route("/admin/productos/eliminar/<int:id>")
def eliminar_producto(id):
    if session.get("rol") != "admin":
        flash("Acceso denegado.", "danger")
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor()

    # Primero borrar los detalles de pedidos relacionados
    cursor.execute("DELETE FROM detalle_pedido WHERE postre_id=%s", (id,))
    conn.commit()

    # Ahora borrar el postre
    cursor.execute("DELETE FROM postres WHERE id=%s", (id,))
    conn.commit()

    cursor.close()
    conn.close()

    flash("Producto eliminado correctamente", "success")
    return redirect(url_for("admin_productos"))



# -------------------- MAIN --------------------
if __name__ == '__main__':
    app.run(debug=True)



