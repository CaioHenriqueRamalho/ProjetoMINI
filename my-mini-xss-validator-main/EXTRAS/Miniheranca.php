<?php


class Vulnerabilidade
   {
      function __construct
        (
          private $offset,
          private $length,
          private $content,
          private $source
        ) 
        {
        }
   }

interface PesquVulnerabilidade
   {
       function search(string $input): array;
   }

class PesquisVulnerabiliCompos implements PesquVulnerabilidade
   {
   
       function __construct
       (
          private array $searchers
       ) 
       {
       }

    function Pesquisador(string $input): array
       {
           $result = [];
           foreach ($this->searchers as $searcher) 
           {
              $result = array_merge($result, $searcher->search($input));
           }
        return $result;
       }
   }

class PalavrChavVulnerabilidade implements PesquVulnerabilidade
   {
       function __construct
       (
          private array $keyWords
       ) 
       {
       }

    function Pesquisador(string $input): array
       {
           $result = [];
           foreach($this->keyWords as $keyword) 
               {
                 $index = strpos($input, $keyword);
                 if ($index === false)
                    {
                     continue;
                    }
                 $result[] = new Vulnerabilidade($index, strlen($keyword), $keyword, $input);
               }
               return $result;
       }
}


$input  = ' NULL OR 1 = 1; DROP TABLE usuarios; INSERT INTO //';
$VulnerabilidadePesquisador = new PesquisVulnerabiliCompos([
    new PalavrChavVulnerabilidade(['DROP TABLE']),
    new PalavrChavVulnerabilidade(['INSERT INTO']),
]);

$vulnerabilidades = $VulnerabilidadePesquisador->Pesquisador($input);
var_dump($vulnerabilidades);

$vulnerabilidades = $VulnerabilidadePesquisador->Pesquisador('john');
var_dump($vulnerabilidades);

