autor:      Marek Žiška
login:      xziska03
predmet:    pds
rok:        2022/2023

Popis súborov a zložiek:
    Zložka pcaps: táto zložka obsahuje pcapng súbory, ktoré som si zachytil na vyrtuálnom stroji pds.ova a taktiež aj súbory zo zadania.
    Zložka csvs: Do tejto zložky sa ukladajú prekonvertované pcapng súbory
    requirements.txt: Súbor, ktorý obsahuje zoznam použitých knižníc
    readme.txt: Popis odovzdaných súborov a návod na spustenie

Popis ako spustiť program:
Pre spustenie programu je nutné nainštalovať zopár knižníc uvedených v requirements.txt. Jednoduchým spôsobom ako to docieliť je vytvorenie si 
virtualneho prostredia (venv) pomocou príkazu "python3 -m venv ${VENV_DIR_NAME}". Následne po vytvorení virtuálneho prostredia ho aktivovať pomocou
source "${VENV_DIR_NAME}/bin/activate". Po aktivovaní stačí spustit inštaláciu pomocou súbora requirements.txt, čo je možné s príkazom 
"pip install -r requirements.txt". Následne je možné program spustiť ako "python3 bt-monitor.py -h", kde návod špecifikuje argumenty programu.
Program funguje primárne s pcap súbormi, pretože ich automaticky filtrujem na účely projektu. Vyfiltrované údaje sú ukladané do csv súborov
ukladaných do zložky csvs, ktoré následne je možné nahrať s argument -csv. Pri nahratí csv súborov nevygenerovaných týmto skriptom dochádza k 
nefunkčným javom.

Stav implementovaného nástroja:
Vzhľadom na časovú vyťaženosť počas semestra som nedokázal naimplementovať všetky časti nástroja. 
Implementácií chýba podpora argumentov -download a -rtable.
