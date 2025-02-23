from flask import Flask, render_template, request, redirect, url_for, session
from routeros_api import RouterOsApiPool
from math import ceil
import codecs  # Para manejar la codificación

app = Flask(__name__)
app.secret_key = 'tu_clave_secreta_aqui'  # Necesario para manejar sesiones

# Función para decodificar respuestas del MikroTik
import chardet

def decode_response(data):
    if isinstance(data, bytes):
        # Detectar la codificación
        encoding = chardet.detect(data)['encoding']
        try:
            return data.decode(encoding, errors='ignore')
        except Exception as e:
            print(f"Error decodificando datos: {e}")
            return "N/A"
    elif isinstance(data, str):
        return data
    else:
        return str(data)

# Ruta principal: formulario de conexión
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Obtener los datos del formulario
        ip = request.form.get('ip')
        user = request.form.get('user')
        password = request.form.get('password')

        # Guardar los datos en la sesión
        session['ip'] = ip
        session['user'] = user
        session['password'] = password

        # Redirigir al dashboard
        return redirect(url_for('clientes'))

    return render_template('index.html')



# Ruta para mostrar clientes
@app.route('/clientes')
def clientes():
    # Verificar si los datos de conexión están en la sesión
    if 'ip' not in session or 'user' not in session or 'password' not in session:
        return redirect(url_for('index'))

    # Obtener el número de página (por defecto, página 1)
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('search', '').strip().lower()  # Obtener la búsqueda
    per_page = 20  # Número de clientes por página

    # Conectar al MikroTik usando RouterOsApiPool
    try:
        pool = RouterOsApiPool(
            session['ip'],
            username=session['user'],
            password=session['password'],
            plaintext_login=True  # Usar autenticación en texto plano (no recomendado en producción)
        )
        api = pool.get_api()  # Obtener la conexión API

        # Obtener información básica del router
        system_info = api.get_resource('/system/resource').get()[0]
        router_name = decode_response(system_info.get('board-name', 'Desconocido'))
        firmware_version = decode_response(system_info.get('version', 'Desconocido'))

        # Obtener la tabla ARP completa
        arp_table = api.get_resource('/ip/arp').get()

        # Obtener la lista de interfaces del router
        interfaces = api.get_resource('/interface').get()
        interface_list = [iface['name'] for iface in interfaces]

        # Decodificar cada entrada de la tabla ARP
        for entry in arp_table:
            entry['address'] = decode_response(entry.get('address', 'N/A'))
            entry['mac-address'] = decode_response(entry.get('mac-address', 'N/A'))
            entry['interface'] = decode_response(entry.get('interface', 'N/A'))
            entry['comment'] = decode_response(entry.get('comment', 'N/A'))

        # Filtrar la tabla ARP si hay una búsqueda
        if search_query:
            arp_table = [
                entry for entry in arp_table
                if search_query in entry['address'].lower() or
                   search_query in entry['mac-address'].lower() or
                   search_query in entry['comment'].lower()
            ]

        # Paginación
        total_clients = len(arp_table)
        total_pages = max(1, ceil(total_clients / per_page))  # Evitar que haya 0 páginas
        start = (page - 1) * per_page
        end = start + per_page
        paginated_arp_table = arp_table[start:end]

    except Exception as e:
        router_name = "Desconocido"
        firmware_version = "Desconocido"
        paginated_arp_table = []
        total_clients = 0
        total_pages = 1
        interface_list = []

        return render_template(
            'clientes.html',
            error=f"No se pudo conectar al router: {str(e)}",
            router_name=router_name,
            firmware_version=firmware_version,
            arp_table=paginated_arp_table,
            page=page,
            total_pages=total_pages,
            total_clients=total_clients,
            search_query=search_query,
            interface_list=interface_list
        )
    finally:
        pool.disconnect()

    return render_template(
        'clientes.html',
        router_name=router_name,
        firmware_version=firmware_version,
        arp_table=paginated_arp_table,
        page=page,
        total_pages=total_pages,
        total_clients=total_clients,
        search_query=search_query,
        interface_list=interface_list
    )

#agregar nuevo cleinte  
@app.route('/agregar_cliente', methods=['POST'])
def agregar_cliente():
    # Verificar si los datos de conexión están en la sesión
    if 'ip' not in session or 'user' not in session or 'password' not in session:
        return redirect(url_for('index'))

    # Obtener los datos del formulario
    new_ip = request.form.get('new_ip')
    new_mac = request.form.get('new_mac')
    new_interface = request.form.get('new_interface')
    new_comment = request.form.get('new_comment')

    # Conectar al MikroTik
    try:
        pool = RouterOsApiPool(
            session['ip'],
            username=session['user'],
            password=session['password'],
            plaintext_login=True
        )
        api = pool.get_api()

        # Agregar una nueva entrada ARP
        api.get_resource('/ip/arp').add(
            address=new_ip,
            mac_address=new_mac,
            interface=new_interface,
            comment=new_comment
        )

        # Redirigir a la página de clientes con un mensaje de éxito
        return redirect(url_for('clientes', success=f"Cliente {new_ip} agregado correctamente"))
    except Exception as e:
        # Redirigir a la página de clientes con un mensaje de error
        return redirect(url_for('clientes', error=f"No se pudo agregar el cliente: {str(e)}"))
    finally:
        pool.disconnect()    
 
 #modificar clientes   
@app.route('/modificar_cliente', methods=['POST'])
def modificar_cliente():
    # Verificar si los datos de conexión están en la sesión
    if 'ip' not in session or 'user' not in session or 'password' not in session:
        return redirect(url_for('index'))

    # Obtener los datos del formulario
    client_id = request.form.get('id')
    new_ip = request.form.get('ip')
    new_mac = request.form.get('mac')
    new_interface = request.form.get('interface')
    new_comment = request.form.get('comment')

    # Conectar al MikroTik
    try:
        pool = RouterOsApiPool(
            session['ip'],
            username=session['user'],
            password=session['password'],
            plaintext_login=True
        )
        api = pool.get_api()

        # Actualizar la entrada ARP
        api.get_resource('/ip/arp').set(
            id=client_id,
            address=new_ip,
            mac_address=new_mac,
            interface=new_interface,
            comment=new_comment
        )

        # Redirigir a la página de clientes con un mensaje de éxito
        return redirect(url_for('clientes', success=f"Cliente {new_ip} modificado correctamente"))
    except Exception as e:
        # Redirigir a la página de clientes con un mensaje de error
        return redirect(url_for('clientes', error=f"No se pudo modificar el cliente: {str(e)}"))
    finally:
        pool.disconnect()



# Ruta para agregar un nuevo cliente
@app.route('/add_client', methods=['POST'])
def add_client():
    if 'ip' not in session or 'user' not in session or 'password' not in session:
        return redirect(url_for('index'))

    # Obtener los datos del formulario
    new_ip = request.form.get('new_ip')
    new_mac = request.form.get('new_mac')
    new_interface = request.form.get('new_interface')
    new_comment = request.form.get('new_comment')

    # Conectar al MikroTik
    try:
        pool = RouterOsApiPool(
            session['ip'],
            username=session['user'],
            password=session['password'],
            plaintext_login=True
        )
        api = pool.get_api()

        # Agregar una nueva entrada ARP
        api.get_resource('/ip/arp').add(
            address=new_ip,
            mac=new_mac,
            interface=new_interface,
            comment=new_comment
        )
        return jsonify({"message": f"Cliente {new_ip} agregado correctamente"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        pool.disconnect()
 
 
     
#para ver los clientes en queues
@app.route('/queues')
def queues():
    # Verificar si los datos de conexión están en la sesión
    if 'ip' not in session or 'user' not in session or 'password' not in session:
        return redirect(url_for('index'))

    try:
        pool = RouterOsApiPool(
            session['ip'],
            username=session['user'],
            password=session['password'],
            plaintext_login=True
        )
        api = pool.get_api()

        # Obtener la lista de colas
        page = request.args.get('page', 1, type=int)
        per_page = 50  # Número de clientes por página
        queues = api.get_resource('/queue/simple').get()

        # Depuración: Imprimir la respuesta completa de la API
        #print(queues)

        # Decodificar y formatear cada entrada de la lista de colas
        for queue in queues:
            queue['name'] = decode_response(queue.get('name', 'N/A'))
            queue['target'] = decode_response(queue.get('target', 'N/A'))

            # Obtener el valor de max-limit (subida/bajada)
            max_limit = queue.get('max-limit', '0/0')  # Valor predeterminado si no está definido

            # Separar los valores de subida y bajada
            max_limit_up, max_limit_down = max_limit.split('/')

            # Depuración: Imprimir los valores antes de formatearlos
            #print(f"max-limit-up: {max_limit_up}, max-limit-down: {max_limit_down}")
        
            # Formatear límite de subida
            if max_limit_up and max_limit_up != '0':
                queue['max-limit-up'] = format_bandwidth(max_limit_up)  # Formatear a "10M", "100M", etc.
            else:
                queue['max-limit-up'] = '0M'  # Valor predeterminado si no está definido

            # Formatear límite de bajada
            if max_limit_down and max_limit_down != '0':
                queue['max-limit-down'] = format_bandwidth(max_limit_down)  # Formatear a "10M", "100M", etc.
            else:
                queue['max-limit-down'] = '0M'  # Valor predeterminado si no está definido

         # Paginación
        total_clients = len(arp_table)  # Total de clientes
        total_pages = ceil(total_clients / per_page)  # Total de páginas
        start = (page - 1) * per_page
        end = start + per_page
        paginated_arp_table = arp_table[start:end]  # Subconjunto de clientes para la página actual

    except Exception as e:
        # En caso de error, definir valores por defecto para las variables de paginación
        router_name = "Desconocido"
        firmware_version = "Desconocido"
        paginated_arp_table = []
        total_clients = 0
        total_pages = 1
        interface_list = []   
        queue['comment'] = decode_response(queue.get('comment', 'N/A'))
        
         # Búsqueda
        search_query = request.args.get('search', '').strip().lower()
        if search_query:
            filtered_queues = [q for q in queues if search_query in q['name'].lower()]
            if not filtered_queues:
                filtered_queues = queues  # Si no encuentra nada, mostrar todos nuevamente
        else:
            filtered_queues = queues

        # Paginación
        page = request.args.get('page', 1, type=int)
        per_page = 20  # Número de clientes por página
        total_queues = len(queues)
        total_pages = ceil(total_queues / per_page)
        start = (page - 1) * per_page
        end = start + per_page
        paginated_queues = filtered_queues[start:end]

    except Exception as e:
        return render_template('queues.html', error=f"No se pudo obtener la lista de colas: {str(e)}")
    finally:
        pool.disconnect()

    return render_template('queues.html', queues=paginated_queues, page=page, total_pages=total_pages, search_query=search_query)
def format_bandwidth(bandwidth):
    """
    Convierte el ancho de banda (en bits/segundo) a un formato legible como "10M", "100M", etc.
    """
    if not bandwidth:
        return '0M'

    # Si el valor ya está en formato legible (por ejemplo, "10M"), devolverlo tal cual
    if isinstance(bandwidth, str) and bandwidth[-1] in ('K', 'M', 'G'):
        return bandwidth

    # Convertir a entero (asumiendo que está en bits/segundo)
    try:
        bandwidth = int(bandwidth)
    except (ValueError, TypeError):
        return '0M'

    # Convertir a Mbps (1 Mbps = 1,000,000 bits/segundo)
    if bandwidth >= 1000000000:  # 1 Gbps
        return f"{bandwidth // 1000000000}G"
    elif bandwidth >= 1000000:  # 1 Mbps
        return f"{bandwidth // 1000000}M"
    elif bandwidth >= 1000:  # 1 Kbps
        return f"{bandwidth // 1000}K"
    else:
        return f"{bandwidth}b"
 
 #modificar el queue   
@app.route('/modificar_cola', methods=['POST'])
def modificar_cola():
    # Verificar si los datos de conexión están en la sesión
    if 'ip' not in session or 'user' not in session or 'password' not in session:
        return redirect(url_for('index'))
    
    # Obtener información básica del router
    system_info = api.get_resource('/system/resource').get()[0]
    router_name = decode_response(system_info.get('board-name', 'Desconocido'))
    firmware_version = decode_response(system_info.get('version', 'Desconocido'))

    # Obtener los datos del formulario
    target_ip = request.form.get('target').split('/')[0]  # Dirección IP de la cola (eliminar /32)
    new_name = request.form.get('name')  # Nuevo nombre de la cola
    new_max_limit_up = request.form.get('max_limit_up')  # Nuevo límite de subida (por ejemplo, "13M")
    new_max_limit_down = request.form.get('max_limit_down')  # Nuevo límite de bajada (por ejemplo, "12M")

    # Depuración: Imprimir los datos recibidos
    #print(f"Datos recibidos: target={target_ip}, name={new_name}, max_limit_up={new_max_limit_up}, max_limit_down={new_max_limit_down}")

    # Convertir los límites de subida y bajada a bits por segundo
    max_limit_up_bps = convert_to_bps(new_max_limit_up)
    max_limit_down_bps = convert_to_bps(new_max_limit_down)

    # Verificar que los límites sean números válidos
    try:
        max_limit_up_bps = int(max_limit_up_bps)
        max_limit_down_bps = int(max_limit_down_bps)
    except ValueError:
        return redirect(url_for('queues', error="Los límites de subida y bajada deben ser números válidos"))

    # Combinar los límites de subida y bajada en el formato "subida/bajada"
    new_max_limit = f"{max_limit_up_bps}/{max_limit_down_bps}"

    # Depuración: Imprimir los límites convertidos
    #print(f"Límites convertidos: {new_max_limit}")

    # Conectar al MikroTik
    try:
        pool = RouterOsApiPool(
            session['ip'],
            username=session['user'],
            password=session['password'],
            plaintext_login=True
        )
        api = pool.get_api()

        # Buscar la cola por su dirección IP (target)
        queues = api.get_resource('/queue/simple').get()
        #print(f"Lista de colas: {queues}")  # Depuración: Imprimir la lista de colas

        queue_to_update = None
        for queue in queues:
            if queue.get('target', '').startswith(target_ip):
                queue_to_update = queue
                break

        if not queue_to_update:
            return redirect(url_for('queues', error=f"No se encontró una cola con la IP {target_ip}"))

        # Depuración: Imprimir la cola encontrada
       # print(f"Cola encontrada: {queue_to_update}")

        if 'id' not in queue_to_update:
            return redirect(url_for('queues', error=f"No se encontró el ID de la cola con la IP {target_ip}"))

        queue_id = queue_to_update['id']  # Obtener el ID de la cola

        # Actualizar la cola
        response = api.get_resource('/queue/simple').set(
            id=queue_id,  # ID de la cola encontrada
            name=new_name,  # Nuevo nombre
            target=target_ip,  # Dirección IP (target)
            max_limit=new_max_limit  # Nuevos límites de subida y bajada
        )
       # print(f"Respuesta de la API: {response}")  # Depuración

        # Redirigir a la página de colas con un mensaje de éxito
        return redirect(url_for('queues', success=f"Cola {target_ip} modificada correctamente"))
    except Exception as e:
        print(f"Error al modificar la cola: {str(e)}")  # Depuración
        return redirect(url_for('queues', error=f"No se pudo modificar la cola: {str(e)}"))
    finally:
        pool.disconnect()  # Cerrar la conexión
        
def convert_to_bps(bandwidth):
    """
    Convierte un valor de ancho de banda (por ejemplo, "13M") a bits por segundo.
    """
    if not bandwidth:
        return 0

    # Si el valor ya está en bits por segundo, devolverlo tal cual
    if isinstance(bandwidth, int):
        return bandwidth

    # Convertir a entero (asumiendo que está en formato legible)
    try:
        if bandwidth.endswith('G'):
            return int(float(bandwidth[:-1]) * 1000000000)  # 1 Gbps = 1,000,000,000 bps
        elif bandwidth.endswith('M'):
            return int(float(bandwidth[:-1]) * 1000000)  # 1 Mbps = 1,000,000 bps
        elif bandwidth.endswith('K'):
            return int(float(bandwidth[:-1]) * 1000)  # 1 Kbps = 1,000 bps
        else:
            return int(bandwidth)  # Asumir que está en bps
    except (ValueError, TypeError):
        return 0

#agregar nueo queues
@app.route('/agregar_cola', methods=['POST'])
def agregar_cola():
    # Verificar si los datos de conexión están en la sesión
    if 'ip' not in session or 'user' not in session or 'password' not in session:
        return redirect(url_for('index'))

    # Obtener los datos del formulario
    new_target = request.form.get('new_target')
    new_name = request.form.get('new_name')
    new_max_limit_up = request.form.get('new_max_limit_up')
    new_max_limit_down = request.form.get('new_max_limit_down')

    # Convertir los límites de subida y bajada a bits por segundo
    max_limit_up_bps = convert_to_bps(new_max_limit_up)
    max_limit_down_bps = convert_to_bps(new_max_limit_down)

    # Combinar los límites de subida y bajada en el formato "subida/bajada"
    new_max_limit = f"{max_limit_up_bps}/{max_limit_down_bps}"

    # Conectar al MikroTik
    try:
        pool = RouterOsApiPool(
            session['ip'],
            username=session['user'],
            password=session['password'],
            plaintext_login=True
        )
        api = pool.get_api()

        # Agregar la nueva cola
        api.get_resource('/queue/simple').add(
            name=new_name,
            target=new_target,
            max_limit=new_max_limit
        )

        # Redirigir a la página de colas con un mensaje de éxito
        return redirect(url_for('queues', success=f"Cola {new_name} agregada correctamente"))
    except Exception as e:
        # Redirigir a la página de colas con un mensaje de error
        return redirect(url_for('queues', error=f"No se pudo agregar la cola: {str(e)}"))
    finally:
        pool.disconnect()
        
def convert_to_bps(bandwidth):
    """
    Convierte un valor de ancho de banda (por ejemplo, "13M") a bits por segundo.
    """
    if not bandwidth:
        return 0

    # Si el valor ya está en bits por segundo, devolverlo tal cual
    if isinstance(bandwidth, int):
        return bandwidth

    # Convertir a entero (asumiendo que está en formato legible)
    try:
        if bandwidth.endswith('G'):
            return int(float(bandwidth[:-1]) * 1000000000)  # 1 Gbps = 1,000,000,000 bps
        elif bandwidth.endswith('M'):
            return int(float(bandwidth[:-1]) * 1000000)  # 1 Mbps = 1,000,000 bps
        elif bandwidth.endswith('K'):
            return int(float(bandwidth[:-1]) * 1000)  # 1 Kbps = 1,000 bps
        else:
            return int(bandwidth)  # Asumir que está en bps
    except (ValueError, TypeError):
        return 0
#bloqueo de ip
@app.route('/firewall/address_lists')
def firewall_address_lists():
    # Verificar si los datos de conexión están en la sesión
    if 'ip' not in session or 'user' not in session or 'password' not in session:
        return redirect(url_for('index'))

    try:
        pool = RouterOsApiPool(
            session['ip'],
            username=session['user'],
            password=session['password'],
            plaintext_login=True
        )
        api = pool.get_api()

        # Obtener las listas de direcciones IP bloqueadas
        address_lists = api.get_resource('/ip/firewall/address-list').get()

        # Formatear la fecha de creación (si está disponible)
        for entry in address_lists:
            if 'creation-time' in entry:
                entry['creation-time'] = format_date(entry['creation-time'])  # Formatear la fecha

        # Búsqueda
        search_query = request.args.get('search', '').strip().lower()
        if search_query:
            filtered_address_lists = [
                entry for entry in address_lists
                if search_query in entry.get('list', '').lower() or
                   search_query in entry.get('address', '').lower()
            ]
        else:
            filtered_address_lists = address_lists

        # Paginación
        page = request.args.get('page', 1, type=int)
        per_page = 20  # Número de entradas por página
        total_entries = len(filtered_address_lists)
        total_pages = ceil(total_entries / per_page)
        start = (page - 1) * per_page
        end = start + per_page
        paginated_address_lists = filtered_address_lists[start:end]

    except Exception as e:
        return render_template('firewall_address_lists.html', error=f"No se pudo obtener la lista de direcciones IP bloqueadas: {str(e)}")
    finally:
        pool.disconnect()

    return render_template(
        'firewall_address_lists.html',
        address_lists=paginated_address_lists,
        page=page,
        total_pages=total_pages,
        search_query=search_query
    )


def format_date(timestamp):
    """
    Formatea la fecha de creación en un formato legible.
    """
    from datetime import datetime
    try:
        # Asumiendo que el timestamp está en formato "Jan/02/2006 15:04:05"
        return datetime.strptime(timestamp, "%b/%d/%Y %H:%M:%S").strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return timestamp  # Devolver el valor original si no se puede formatear

@app.route('/firewall/address_lists/delete/<id>')
def delete_address_list_entry(id):
    try:
        pool = RouterOsApiPool(
            session['ip'],
            username=session['user'],
            password=session['password'],
            plaintext_login=True
        )
        api = pool.get_api()

        # Eliminar la entrada por su ID
        api.get_resource('/ip/firewall/address-list').remove(id=id)

        return redirect(url_for('firewall_address_lists', success="Entrada eliminada correctamente"))
    except Exception as e:
        return redirect(url_for('firewall_address_lists', error=f"No se pudo eliminar la entrada: {str(e)}"))
    finally:
        pool.disconnect()

@app.route('/block_ip', methods=['POST'])
def block_ip():
    # Verificar si los datos de conexión están en la sesión
    if 'ip' not in session or 'user' not in session or 'password' not in session:
        return redirect(url_for('index'))

    try:
        pool = RouterOsApiPool(
            session['ip'],
            username=session['user'],
            password=session['password'],
            plaintext_login=True
        )
        api = pool.get_api()

        # Obtener los datos del formulario
        ip = request.form.get('ip')
        name = request.form.get('name')

        # Agregar la IP a la lista de bloqueos en el firewall
        api.get_resource('/ip/firewall/address-list').add(
            list="blocked",  # Nombre de la lista de bloqueos
            address=ip,
            comment=name
        )

        return redirect(url_for('clientes', success=f"IP {ip} bloqueada correctamente"))
    except Exception as e:
        return redirect(url_for('clientes', error=f"No se pudo bloquear la IP: {str(e)}"))
    finally:
        pool.disconnect()
    
    
# Ruta para cerrar sesión
@app.route('/logout')
def logout():
    # Limpiar la sesión
    session.clear()
    return redirect(url_for('index'))

# Iniciar la aplicación Flask
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)