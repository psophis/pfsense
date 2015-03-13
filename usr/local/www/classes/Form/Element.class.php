<?php

class Form_Element
{
	protected $_classes = array();
	protected $_attributes = array();
	protected $_parent;

	public function addClass()
	{
		foreach (func_get_args() as $class) {
			$this->_classes[$class] = true;
		}

		return $this;
	}

	public function removeClass($class)
	{
		unset($this->_classes[$class]);

		return $this;
	}

	public function getHtmlClass($wrapped = true)
	{
		if (empty($this->_classes)) {
			return '';
		}

		$list = implode(' ', array_keys($this->_classes));

		if (!$wrapped) {
			return $list;
		}

		return 'class="'. $list .'"';
	}

	public function setAttribute($key, $value = null)
	{
		$this->_attributes[ $key ] = $value;

		return $this;
	}

	public function getAttribute($name)
	{
		return $this->_attributes[$name];
	}

	public function removeAttribute($name)
	{
		unset($this->_attributes[$name]);

		return $this;
	}

	public function getHtmlAttribute()
	{
		$attributes = '';
		foreach ($this->_attributes as $key => $value) {
			$attributes .= ' ' . $key . (isset($value) ? '="' . htmlspecialchars($value) . '"' : '');
		}

		return $attributes;
	}

	protected function _setParent(Form_Element $parent)
	{
		$this->_parent = $parent;
	}
}
