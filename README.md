# Engenharia reversa
[![xiosec - Engenharia reversa](https://img.shields.io/static/v1?label=xiosec&message=Engenharia reversa&color=blue&logo=github)](https://github.com/xiosec/Engenharia reversa)
[![stars - Engenharia reversa](https://img.shields.io/github/stars/xiosec/Reverse-engineering?style=social)](https://github.com/xiosec/Reverse-engineering)
[![forks - Engenharia reversa](https://img.shields.io/github/forks/xiosec/Reverse-engineering?style=social)](https://github.com/xiosec/Reverse-engineering)
[![Lançamento do GitHub](https://img.shields.io/github/release/xiosec/Reverse-engineering?include_prereleases=&sort=semver)](https://github.com/xiosec/Reverse-engineering/releases/)
[![Licença](https://img.shields.io/badge/License-MIT-blue)](#license)
[![problemas - Engenharia reversa](https://img.shields.io/github/issues/xiosec/Reverse-engineering)](https://github.com/xiosec/Reverse-engineering/issues)

<strong>Um conjunto de ferramentas para engenharia reversa de software.</strong><br>
<a href="#license"><img align="right" src="resources/images/logo.png"></a>


<i>Nas tabelas a seguir, você pode encontrar as ferramentas necessárias de acordo com o título.</i>
* [Engenharia reversa](https://github.com/xiosec/Reverse-engineering)
  * [Depuração](#-depuração)
  * [Desmontadores](#-desmontadores)
  * [Android](#-android)
  * [Editores Hex](#-hex-editors)
  * [Formato binário](#-binary-format)
  * [Análise Binária](#-binary-analysis)
  * [Análise de Bytecode](#-bytecode-analysis)
  * [Análise dinâmica](#-dynamic-analysis)
  * [Análise de Documentos](#-document-analysis)
  * [Scripting](#-scripting)
  * [Mac Decrypt](#-mac-decrypt)
  * [📔 Livros de Engenharia Reversa](#-reverse-engineering-books)
  * [📎 Alvo e prática](#-alvo-e-prática)


## ⚙ Depuração
<i>Ferramentas de depuração</i>

| Nome | Descrições | Download |
| ----- | ------------ | -------- |
| **`WinDbg`** | O WDK é usado para desenvolver, testar e implantar drivers do Windows. | [Download](https://msdn.microsoft.com/en-us/windows/hardware/hh852365.aspx) |
| **`OllyDbg v1.10`** | OllyDbg é um depurador de análise de nível de assembler de 32 bits para Microsoft® Windows®. A ênfase na análise de código binário o torna particularmente útil em casos onde a fonte não está disponível. | [Download](http://www.ollydbg.de/) |
| **`OllyDbg v2.01`** | OllyDbg (nomeado em homenagem ao seu autor, Oleh Yuschuk) é um depurador x86 que enfatiza a análise de código binário, o que é útil quando o código-fonte não está disponível. |[Download](http://www.ollydbg.de/version2.html) |
| **`x64dbg`** | Um depurador x64/x32 de código aberto para Windows. | [Download](http://x64dbg.com/#start) |
| **`gdb`** | O GDB, o depurador do Projeto GNU, permite que você veja o que está acontecendo `dentro` de outro programa enquanto ele é executado -- ou o que outro programa estava fazendo no momento em que travou. | [Download](https://www.gnu.org/software/gdb/) |
| **`vdb`** | Um desmontador combinado/análise estática/execução simbólica/framework depurador. Mais documentação está em andamento. | [github](https://github.com/vivisect/vivisect) |
| **`lldb`** | LLDB é um depurador de última geração e alto desempenho. Ele é construído como um conjunto de componentes reutilizáveis ​​que alavancam fortemente as bibliotecas existentes no Projeto LLVM maior, como o analisador de expressões Clang e o desmontador LLVM. | [Download](http://lldb.llvm.org/) |
| **`qira`** | Todo o estado é rastreado enquanto um programa está em execução, para que você possa depurar no passado. | [Download](http://qira.me/) |
| **`unicorn`** | Estrutura do emulador de CPU Unicorn (ARM, AArch64, M68K, Mips, Sparc, X86). | [github](https://github.com/unicorn-engine/unicorn) |
| **`Immunity Debugger`** | As interfaces do Immunity Debugger incluem a GUI e uma linha de comando. A linha de comando está sempre disponível na parte inferior da GUI. Ela permite que o usuário digite atalhos como se estivessem em um depurador baseado em texto típico, como WinDBG ou GDB. O Immunity implementou aliases para garantir que seus usuários do WinDBG não precisem ser retreinados e obtenham o aumento total de produtividade que vem da melhor interface de depurador do mercado. | [Download](https://www.immunityinc.com/products/debugger/) |
## 🔩 Desmontadores
<i>Desmontadores</i>

| Nome | Descrições | Download |
| ----- | ------------ | -------- |
| **`IDA Pro`** | O IDA Pro como um desmontador é capaz de criar mapas de sua execução para mostrar as instruções binárias que são realmente executadas pelo processador em uma representação simbólica (linguagem de montagem). | [Download](https://www.hex-rays.com/products/ida/index.shtml) |
| **`GHIDRA`** | Um conjunto de ferramentas de engenharia reversa de software (SRE) desenvolvido pela Diretoria de Pesquisa da NSA em apoio à missão de Segurança Cibernética. | [Download](https://ghidra-sre.org/) |
| **`Binary Ninja`** | Nosso descompilador integrado funciona com todas as nossas arquiteturas a um preço único e se baseia em uma poderosa família de ILs chamada BNIL. | [Download](https://binary.ninja/) |
| **`Radare`** | Desmonte (e monte) para muitas arquiteturas diferentes. | [Download](http://www.radare.org/r/) |
| **`Hopper`** | Hopper Disassembler, a ferramenta de engenharia reversa que permite desmontar, descompilar e depurar seus aplicativos. | [Download](http://hopperapp.com/) |
| **`objdump`** | objdump exibe informações sobre um ou mais arquivos de objeto. As opções controlam quais informações específicas exibir. | [Download](http://linux.die.net/man/1/objdump) |
| **`fREedom`** | desmontador baseado em capstone para extração para binnavi. | [Download](https://github.com/cseagle/fREedom) |

## 📱 Android
<i>Ferramentas Android</i>
| Nome | Descrições | Download |
| ----- | ------------ | -------- |
| **`Android Studio`** | O Android Studio fornece as ferramentas mais rápidas para criar aplicativos em todos os tipos de dispositivos Android. | [Download](http://developer.android.com/sdk/index.html) |
| **`APKtool`** | Uma ferramenta para engenharia reversa de apps Android binários fechados de terceiros. Ela pode decodificar recursos para uma forma quase original e reconstruí-los após fazer algumas modificações. | [Download](https://ibotpeaches.github.io/Apktool/) |
| **`dex2jar`** | Ferramentas para trabalhar com arquivos .dex do Android e .class do Java. | [github](https://github.com/pxb1988/dex2jar) |
| **`IDA Pro`** | O IDA Pro como um desmontador é capaz de criar mapas de sua execução para mostrar as instruções binárias que são realmente executadas pelo processador em uma representação simbólica (linguagem de montagem). | [Download](https://hex-rays.com/ida-pro/) |
| **`JaDx`** | Descompilador Dex para Java. | [github](https://github.com/skylot/jadx) |
| **`APKinspector`** | O APKinspector é uma ferramenta GUI poderosa para analistas analisarem os aplicativos Android. | [github](https://github.com/honeynet/apkinspector/) |
| **`objeção`** | 📱 objeção - exploração móvel em tempo de execução | [github](https://github.com/sensepost/objection) |
| **`Sign.jar`** | Sign.jar assina automaticamente um apk com o certificado de teste do Android. | [github](https://github.com/appium-boneyard/sign) |
| **`FindSecurityBugs`** | FindSecurityBugs é uma extensão para FindBugs que inclui regras de segurança para aplicativos Java. | [Download](http://findbugs.sourceforge.net/) |
| **`Quick Android Review Kit (Qark)`** | Ferramenta para procurar diversas vulnerabilidades de aplicativos Android relacionadas à segurança | [github](https://github.com/linkedin/qark) |
| **`AndroBugs Framework`** | AndroBugs Framework é um scanner de vulnerabilidades Android eficiente que ajuda desenvolvedores ou hackers a encontrar potenciais vulnerabilidades de segurança em aplicativos Android. Não há necessidade de instalar no Windows. | [github](https://github.com/AndroBugs/AndroBugs_Framework) |
| **`Simplify`** | Ferramenta para desofuscar pacotes Android em Classes.dex, que pode usar Dex2jar e JD-GUI para extrair conteúdo do arquivo dex. | [github](https://github.com/CalebFenton/simplify) |
| **`Android backup extractor`** | Utilitário para extrair e reempacotar backups do Android criados com adb backup (ICS+). Mais informações sobre adb backup aqui. | [github](https://github.com/nelenkov/android-backup-extractor) |
| **`Xposed framework`** | Use este fórum para conversar sobre o Xposed framework e módulos para modificar seu dispositivo sem instalar uma ROM personalizada | [Download](https://forum.xda-developers.com/f/xposed-general.3094/) |
| **`AndBug`** | AndBug é um depurador direcionado à máquina virtual Dalvik da plataforma Android, destinado a engenheiros reversos e desenvolvedores. | [github](https://github.com/swdunlop/AndBug) |
| **`Introspy-Android`** | Ferramenta Blackbox para ajudar a entender o que um aplicativo Android está fazendo em tempo de execução e auxiliar na identificação de potenciais problemas de segurança. | [github](https://github.com/iSECPartners/Introspy-Android) |
| **`android-ssl-bypass`** | Esta é uma ferramenta de depuração do Android que pode ser usada para ignorar SSL, mesmo quando o pinning de certificado é implementado, bem como outras tarefas de depuração. A ferramenta é executada como um console interativo. | [github](https://github.com/iSECPartners/android-ssl-bypass) |

## 🗄 Editores Hex
<i>Editores Hexadecimais</i>

| Nome | Descrições | Download |
| ----- | ------------ | -------- |
| **`HxD`** | O HxD é um editor hexadecimal rápido e cuidadosamente projetado que, além da edição de disco bruto e modificação da memória principal (RAM), manipula arquivos de qualquer tamanho. | [Download](https://mh-nexus.de/en/hxd/) |
| **`010 Editor`** | Por que o 010 Editor é tão poderoso? Ao contrário dos editores hexadecimais tradicionais que exibem apenas os bytes hexadecimais brutos de um arquivo. | [Download](https://www.sweetscape.com/010editor/) |
| **`Hex Workshop`** | O Hex Workshop Hex Editor é um conjunto de ferramentas de desenvolvimento hexadecimal para Microsoft Windows, combinando edição binária avançada com a facilidade e flexibilidade de um processador de texto. | [Download](http://www.hexworkshop.com/) |
| **`HexFiend`** | Um editor hexadecimal de código aberto rápido e inteligente para macOS. | [Download](https://hexfiend.com/) |
| **`Hiew`** | visualize e edite arquivos de qualquer tamanho nos modos texto, hexadecimal e decodificação. | [Download](http://www.hiew.ru/) |
| **`hecate`** | O editor hexadecimal do inferno!. | [github](https://github.com/evanmiller/hecate) |

## 📐 Formato binário
<i>Ferramentas de formato binário</i>

| Nome | Descrições | Download |
| ----- | ------------ | -------- |
| **`Cerbero Profiler`** | Inspecionar um arquivo é uma tarefa primária para todo profissional de baixo nível, seja para reversão, triagem de malware, perícia ou desenvolvimento de software. | [Download](https://cerbero.io/) |
| **`Detect It Easy`** | Detect It Easy, ou abreviado “DIE” é um programa para determinar tipos de arquivos. | [Download](https://horsicq.github.io/) |
| **`MachoView`** | MachOView é um navegador de arquivos Mach-O visual. Ele fornece uma solução completa para explorar e editar no local binários Intel e ARM. | [Download](http://sourceforge.net/projects/machoview/) |
| **`codesign`** | Uso de informações de assinatura de código: codesign -dvvv nome do arquivo. | [Download](https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man1/codesign.1.html) |

## 🔬 Análise Binária
<i>Recursos de Análise Binária</i>

| Nome | Descrições | Download |
| ----- | ------------ | -------- |
| **`Mobius Resources`** | Descompactando ofuscadores de virtualização. | [Download](https://www.msreverseengineering.com/research/) |
| **`bap`** | A Plataforma de Análise Binária da Carnegie Mellon University (CMU BAP) é um conjunto de utilitários e bibliotecas que permite a análise de programas na representação de código de máquina. | [github](https://github.com/BinaryAnalysisPlatform/bap) |
| **`angr`** | angr é uma estrutura de análise binária independente de plataforma. | [github](https://github.com/angr/angr) |

## 🔎 Análise de Bytecode
<i>Ferramentas de análise de bytecode</i>

| Nome | Descrições | Download |
| ----- | ------------ | -------- |
| **`dnSpy`** | dnSpy é um depurador e editor de assembly .NET. | [github](https://github.com/dnSpy/dnSpy) |
| **`Bytecode Viewer`** | SEIS DESCOMPILADORES JAVA DIFERENTES, DOIS EDITORES DE BYTECODE, UM COMPILADOR JAVA, PLUGINS, PESQUISA, SUPORTA CARREGAMENTO DE CLASSES, JARS, APKS ANDROID E MAIS. | [Download](https://bytecodeviewer.com/) |
| **`JPEXS Free Flash Decompiler`** | Descompilador e editor flash SWF de código aberto. | [github](https://github.com/jindrapetrik/jpexs-decompiler) |
| **`Projeto JD`** | O “projeto Java Decompiler” visa desenvolver ferramentas para descompilar e analisar o “byte code” do Java 5 e versões posteriores. O JD-GUI é um utilitário gráfico independente que exibe códigos-fonte Java de arquivos “.class”. Você pode navegar pelo código-fonte reconstruído com o JD-GUI para acesso instantâneo a métodos e campos. O JD-Eclipse é um plug-in para a plataforma Eclipse. Ele permite que você exiba todas as fontes Java durante seu processo de depuração, mesmo que você não tenha todas elas. O JD-Core é uma biblioteca que reconstrói o código-fonte Java de um ou mais arquivos “.class”. O JD-Core pode ser usado para recuperar código-fonte perdido e explorar a fonte de bibliotecas de tempo de execução Java. Novos recursos do Java 5, como anotações, genéricos ou tipo “enum”, são suportados. O JD-GUI e o JD-Eclipse incluem a biblioteca JD-Core. JD-Core, JD-GUI e JD-Eclipse são projetos de código aberto lançados sob a licença GPLv3. | [Download](http://java-decompiler.github.io/) |

## 🔨 Análise dinâmica
<i>Ferramentas de Análise Dinâmica</i>

| Nome | Descrições | Download |
| ----- | ------------ | -------- |
| **`Process Explorer v16.42`** | O Process Explorer mostra informações sobre quais identificadores e DLLs os processos abriram ou carregaram. | [Download](https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer) |
| **`Process Monitor v3.82`** | O Process Monitor é uma ferramenta de monitoramento avançada para Windows que mostra o sistema de arquivos em tempo real, o Registro e a atividade de processos/threads. | [Download](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) |
| **`Autoruns para Windows v13.100`** | Este utilitário, que tem o conhecimento mais abrangente de locais de inicialização automática de qualquer monitor de inicialização. | [Download](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) |
| **`Noriben`** | Noriben é um script baseado em Python que funciona em conjunto com o Sysinternals Procmon para coletar, analisar e relatar automaticamente indicadores de tempo de execução de malware. | [github](https://github.com/Rurik/Noriben) |
| **`API Monitor`** | O API Monitor é um software gratuito que permite monitorar e controlar chamadas de API feitas por aplicativos e serviços. | [Download](http://www.rohitab.com/apimonitor) |
| **`INetSim`** | INetSim é um conjunto de software para simular serviços comuns de internet em um ambiente de laboratório, por exemplo, para analisar o comportamento de rede de amostras de malware desconhecidas. | [Download](https://www.inetsim.org/) |
| **`SmartSniff`** | O SmartSniff é um utilitário de monitoramento de rede que permite capturar pacotes TCP/IP que passam pelo seu adaptador de rede. | [Download](http://www.nirsoft.net/utils/smsniff.html) |
| **`TCPView`** | O TCPView é um programa do Windows que mostrará listagens detalhadas de todos os pontos de extremidade TCP e UDP no seu sistema, incluindo os endereços locais e remotos e o estado das conexões TCP. | [Download](https://docs.microsoft.com/en-us/sysinternals/downloads/tcpview) |
| **`Wireshark`** | O Wireshark é o analisador de protocolo de rede mais utilizado e mais importante do mundo. | [Download](https://www.wireshark.org/download.html) |
| **`Fakenet`** | FakeNet é uma ferramenta que auxilia na análise dinâmica de software malicioso. | [Download](https://practicalmalwareanalysis.com/fakenet/) |
| **`Volatility`** | Uma estrutura avançada de análise forense de memória. | [github](https://github.com/volatilityfoundation/volatility) |
| **`LiME`** | Um Módulo Kernel Carregável (LKM) que permite a aquisição de memória volátil de dispositivos Linux e baseados em Linux. | [github](https://github.com/504ensicsLabs/LiME) |
| **`Cuckoo`** | O Cuckoo Sandbox é o principal sistema de análise automatizada de malware de código aberto. | [Download](https://cuckoosandbox.org/) |
| **`Objective-See Utilities`** | Ferramentas de segurança gratuitas para Mac | [Download](https://objective-see.com/products.html) |
| **`XCode Instruments`** | Guia do usuário do XCode Instruments para monitoramento de arquivos e processos. | [Download](https://developer.apple.com/xcode/download/) |
| **`fs_usage`** | relata chamadas de sistema e falhas de página relacionadas à atividade do sistema de arquivos em tempo real. E/S de arquivo: fs_usage -w -f filesystem. | [Download](https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man1/fs_usage.1.html) |
| **`dmesg`** | exibe o buffer de mensagens do sistema. | [Download](https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man8/dmesg.8.html) |

## 📚 Análise de Documentos
<i>Ferramentas de análise de documentos</i>

| Nome | Descrições | Download |
| ----- | ------------ | -------- |
| **`Ole Tools`** | python-oletools é um pacote de ferramentas python para analisar arquivos Microsoft OLE2. | [Download](http://www.decalage.info/python/oletools) |
| **`Ferramentas de PDF do Didier`** | Esta ferramenta analisará um documento PDF para identificar os elementos fundamentais usados ​​no arquivo analisado. | [Download](https://blog.didierstevens.com/programs/pdf-tools/) |
| **`Origami`** | Origami é um framework Ruby projetado para analisar, analisar e forjar documentos PDF. | [github](https://github.com/cogent/origami-pdf) |

## 🔗 Roteiro
<i>Script</i>

| Nome | Descrições | Download |
| ----- | ------------ | -------- |
| **`IDA Python Src`** | Projeto IDAPython para o IDA Pro da Hex-Ray. | [github](https://github.com/idapython/src) |
| **`IDC Functions Doc`** | As seguintes convenções são usadas nas descrições de funções. | [Download](https://hex-rays.com/products/ida/support/idadoc/162.shtml) |
| **`Concurso de plugins IDA`** | O concurso de plugins Hex-Rays 2021 começou oficialmente. | [Download](https://hex-rays.com/contests/) |
| **`Lista de plugins IDA do onehawt`** | Uma lista de plugins IDA. | [github](https://github.com/onethawt/idaplugins-list) |
| **`pefile`** | pefile é um módulo Python multiplataforma para analisar e trabalhar com arquivos Portable Executable (PE). A maioria das informações contidas nos cabeçalhos dos arquivos PE é acessível, assim como todos os detalhes e dados das seções. | [github](https://github.com/erocarrera/pefile) |

## 💻 Mac Descriptografar
| Nome | Descrições | Download |
| ----- | ------------ | -------- |
| **`Cerbero Profiler`** | Embora este PoC seja sobre análise estática, é muito diferente de aplicar um compactador a um malware. | [Download](https://cerbero-blog.com/?p=1311) |
| **`AppEncryptor`**| Uma ferramenta de linha de comando para aplicar ou remover a Apple Binary Protection de um aplicativo. | [github](https://github.com/AlanQuatermain/appencryptor) |
| **`Class-dump`** | Este é um utilitário de linha de comando para examinar as informações de tempo de execução do Objective-C armazenadas em arquivos Mach-O. | [Download](http://stevenygard.com/projects/class-dump/) |
| **`readmem`** | Um pequeno utilitário de userland do OS X/iOS para despejar memória de processos. | [github](https://github.com/gdbinit/readmem) |

## 📔 Livros de Engenharia Reversa

| Nome | Descrições |
| ----- | ------------ |
| **`The IDA Pro Book`** | [Descrição](http://amzn.to/2jTicOg) |
| **`Livro Radare2`** | [página do github](https://www.gitbook.com/book/radare/radare2book/details) |
| **`Engenharia reversa para iniciantes`** | [Descrição](http://beginners.re/) |
| **`A Arte da Memória Forense`** | [Descrição](http://amzn.to/2jMJQs0) |
| **`Arte da Avaliação de Segurança de Software`** | [Descrição](http://amzn.to/2jlvtyt) |
| **`Engenharia reversa do iOS`** | [Descrição](https://github.com/iosre/iOSAppReverseEngineering) |

# 📎 Alvo e Prática

| Nome | Descrições |
| ----- | ----------- |
| **`OSX Crackmes`** | [Descrição](https://reverse.put.as/crackmes/) |
| **`Desafios da ESET`** | [Descrição](http://www.joineset.com/jobs-analyst.html) |
| **`Desafios do Flare-on`** | [Descrição](http://flare-on.com/) |
| **`Arquivos CTF do Github`** | [página do github](http://github.com/ctfs/) |
| **`Desafios da Engenharia Reversa`** | [Descrição](http://challenges.re/) |
| **`Lista Negra de Malware`** | [Descrição](http://www.malwareblacklist.com/showMDL.php) |
| **`malwr.com`** | [Descrição](https://malwr.com/) |

## Licença

Lançado sob [MIT](/LICENSE) por [@xiosec](https://github.com/xiosec).
