@echo off
echo "Instalando virtualenv para crear ambientes virtuales"
pip install virtualenv

echo Creando un ambiente virtual especifico para este proyecto
python -m virtualenv proyecto1

echo Se ha creado el ambiente virtual proyecto1 y se activara
call .\proyecto1\Scripts\activate

echo Instalando requerimientos
pip install -r requerimientos.txt

echo Copiando los archivos del proyecto al ambiente virtual
xcopy templates proyecto1/templates /I /E
xcopy app.py proyecto1/ 

echo Iniciando el servidor
python app.py